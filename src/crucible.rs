// userland/corinth/src/crucible.rs
//
// CRUCIBLE — Multi-Pass IR Mutation Engine
//
// Operates on a simplified bytecode IR defined for Corinth:
//
//   IR encoding (each instruction = 4 bytes):
//     byte 0: opcode
//     byte 1: operand A
//     byte 2: operand B
//     byte 3: flags
//
//   Opcodes relevant to mutation:
//     0x00 = NOP
//     0x01 = MOV   dst, src
//     0x02 = ADD   dst, src
//     0x03 = JMP   target_offset (relative, signed i8 in operand A)
//     0x04 = JZ    target_offset, cond_reg
//     0x05 = CALL  fn_id
//     0x06 = RET
//     0x07 = LOOP_BEGIN  count (known iteration count in operand A)
//     0x08 = LOOP_END    (matches most recent LOOP_BEGIN)
//     0x09 = INLINE_SITE fn_id (placeholder: replace with inlined body)
//     0xFF = DEAD  (marked dead by DCE pass)
//
// Passes applied in order per OptimizationFocus:
//   MaximumThroughput:  Inline → Unroll → DCE
//   ThermalEfficiency:  DCE only (smaller code = less fetch energy)
//   MemoryCompression:  DCE → compact (repack instructions, elide NOPs)

#![allow(dead_code)]

use crate::dna::OptimizationFocus;

pub const MAX_IR_INSTRUCTIONS: usize = 16384;
pub const MAX_INLINE_DEPTH:    usize = 4;
pub const MAX_UNROLL_FACTOR:   usize = 8;
pub const MAX_FUNCTIONS:       usize = 64;
pub const INSTRUCTION_BYTES:   usize = 4;

// ─────────────────────────────────────────────
// IR INSTRUCTION
// ─────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instr {
    pub opcode: u8,
    pub a:      u8,
    pub b:      u8,
    pub flags:  u8,
}

impl Instr {
    pub const NOP:  Self = Self { opcode: 0x00, a: 0, b: 0, flags: 0 };
    pub const DEAD: Self = Self { opcode: 0xFF, a: 0, b: 0, flags: 0 };

    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self { opcode: bytes[0], a: bytes[1], b: bytes[2], flags: bytes[3] }
    }
    pub const fn to_bytes(self) -> [u8; 4] {
        [self.opcode, self.a, self.b, self.flags]
    }
    pub const fn is_dead(self) -> bool { self.opcode == 0xFF }
    pub const fn is_nop(self)  -> bool { self.opcode == 0x00 }
    pub const fn is_terminator(self) -> bool {
        matches!(self.opcode, 0x03 | 0x04 | 0x06) // JMP, JZ, RET
    }
}

// ─────────────────────────────────────────────
// IR BUFFER — decoded instruction array
// ─────────────────────────────────────────────

pub struct IrBuffer {
    pub instrs:  [Instr; MAX_IR_INSTRUCTIONS],
    pub len:     usize,
}

impl IrBuffer {
    pub fn new() -> Self {
        Self { instrs: [Instr::NOP; MAX_IR_INSTRUCTIONS], len: 0 }
    }

    pub fn decode_from(bytes: &[u8]) -> Self {
        let mut buf = Self::new();
        let chunks = bytes.len() / INSTRUCTION_BYTES;
        let count = chunks.min(MAX_IR_INSTRUCTIONS);
        for i in 0..count {
            let off = i * INSTRUCTION_BYTES;
            let b = [bytes[off], bytes[off+1], bytes[off+2], bytes[off+3]];
            buf.instrs[i] = Instr::from_bytes(b);
        }
        buf.len = count;
        buf
    }

    pub fn encode_to(&self, output: &mut [u8]) -> usize {
        let count = self.len.min(output.len() / INSTRUCTION_BYTES);
        for i in 0..count {
            let off = i * INSTRUCTION_BYTES;
            let b = self.instrs[i].to_bytes();
            output[off..off+4].copy_from_slice(&b);
        }
        count * INSTRUCTION_BYTES
    }

    pub fn live_count(&self) -> usize {
        self.instrs[..self.len].iter().filter(|i| !i.is_dead()).count()
    }
}

// ─────────────────────────────────────────────
// PASS 1: INLINER
// Finds INLINE_SITE(fn_id) instructions and replaces them
// with the actual function body (looked up from a function table).
// Prevents recursive infinite inlining via depth counter.
// ─────────────────────────────────────────────

pub struct FunctionTable {
    pub entries: [FnEntry; MAX_FUNCTIONS],
    pub count:   usize,
}

#[derive(Clone, Copy)]
pub struct FnEntry {
    pub fn_id:       u8,
    pub start:       usize,  // instruction index in a shared body buffer
    pub len:         usize,  // instruction count
    pub inline_cost: u8,     // estimated cycles saved by inlining
}

impl FunctionTable {
    pub const fn new() -> Self {
        Self { entries: [FnEntry { fn_id: 0, start: 0, len: 0, inline_cost: 0 }; MAX_FUNCTIONS], count: 0 }
    }

    pub fn register(&mut self, entry: FnEntry) -> bool {
        if self.count >= MAX_FUNCTIONS { return false; }
        self.entries[self.count] = entry;
        self.count += 1;
        true
    }

    pub fn lookup(&self, fn_id: u8) -> Option<&FnEntry> {
        self.entries[..self.count].iter().find(|e| e.fn_id == fn_id)
    }
}

pub struct InlinerPass {
    pub inline_depth:  usize,
    pub sites_inlined: u32,
    pub bytes_saved:   u32,
}

impl InlinerPass {
    pub fn new() -> Self { Self { inline_depth: 0, sites_inlined: 0, bytes_saved: 0 } }

    /// Inline all INLINE_SITE(fn_id) instructions in `buf`, using bodies from `body_buf`.
    /// `body_buf`: a flat array of instructions for all functions (FnEntry.start indexes into it).
    pub fn run(
        &mut self,
        buf: &mut IrBuffer,
        body_buf: &[Instr; MAX_IR_INSTRUCTIONS],
        table: &FunctionTable,
    ) {
        if self.inline_depth >= MAX_INLINE_DEPTH { return; }
        self.inline_depth += 1;

        let mut i = 0usize;
        while i < buf.len {
            let instr = buf.instrs[i];
            if instr.opcode != 0x09 { i += 1; continue; } // INLINE_SITE

            let fn_id = instr.a;
            let entry = match table.lookup(fn_id) {
                Some(e) => *e,
                None => { i += 1; continue; }
            };

            // Guard: don't inline if body is too large (would overflow buffer)
            if buf.len + entry.len > MAX_IR_INSTRUCTIONS { i += 1; continue; }

            // Shift everything after i rightward by (entry.len - 1) to make room
            let shift = entry.len.saturating_sub(1);
            if shift > 0 {
                let move_count = buf.len.saturating_sub(i + 1);
                for k in (0..move_count).rev() {
                    let src = i + 1 + k;
                    let dst = src + shift;
                    if dst < MAX_IR_INSTRUCTIONS {
                        buf.instrs[dst] = buf.instrs[src];
                    }
                }
                buf.len = (buf.len + shift).min(MAX_IR_INSTRUCTIONS);
            }

            // Copy function body into the gap
            for k in 0..entry.len {
                let dst = i + k;
                let src = entry.start + k;
                if dst < MAX_IR_INSTRUCTIONS && src < MAX_IR_INSTRUCTIONS {
                    buf.instrs[dst] = body_buf[src];
                }
            }

            self.sites_inlined += 1;
            self.bytes_saved += entry.inline_cost as u32;
            // Don't advance i — re-scan the newly inlined instructions
        }

        self.inline_depth -= 1;
    }
}

// ─────────────────────────────────────────────
// PASS 2: DEAD CODE ELIMINATOR
// Reachability analysis: marks unreachable instructions as DEAD.
// Uses a bitset (u64 array) for O(N/64) marking.
// Algorithm: BFS from entry point (instruction 0),
//   following JMP/JZ targets and sequential flow.
//   Any instruction not reached = DEAD.
// ─────────────────────────────────────────────

pub struct DcePass {
    pub dead_count:    u32,
    pub bytes_removed: u32,
}

impl DcePass {
    pub fn new() -> Self { Self { dead_count: 0, bytes_removed: 0 } }

    pub fn run(&mut self, buf: &mut IrBuffer) {
        if buf.len == 0 { return; }

        const BITSET_WORDS: usize = MAX_IR_INSTRUCTIONS / 64 + 1;
        let mut reachable = [0u64; BITSET_WORDS];

        let mut queue  = [0u16; MAX_IR_INSTRUCTIONS];
        let mut qhead  = 0usize;
        let mut qtail  = 0usize;

        // Mark entry point reachable
        Self::mark(&mut reachable, 0);
        queue[qtail] = 0; qtail += 1;

        while qhead < qtail {
            let pc = queue[qhead] as usize; qhead += 1;
            if pc >= buf.len { continue; }

            let instr = buf.instrs[pc];
            if instr.is_dead() { continue; }

            // Sequential successor (unless unconditional JMP or RET)
            if !matches!(instr.opcode, 0x03 | 0x06) {
                let next = pc + 1;
                if next < buf.len && !Self::is_marked(&reachable, next) {
                    Self::mark(&mut reachable, next);
                    if qtail < MAX_IR_INSTRUCTIONS { queue[qtail] = next as u16; qtail += 1; }
                }
            }

            // Branch/jump target
            match instr.opcode {
                0x03 | 0x04 => { // JMP, JZ
                    let offset = instr.a as i8;
                    let target = (pc as isize + offset as isize) as usize;
                    if target < buf.len && !Self::is_marked(&reachable, target) {
                        Self::mark(&mut reachable, target);
                        if qtail < MAX_IR_INSTRUCTIONS { queue[qtail] = target as u16; qtail += 1; }
                    }
                }
                _ => {}
            }
        }

        // Mark unreachable as DEAD
        for i in 0..buf.len {
            if !Self::is_marked(&reachable, i) && !buf.instrs[i].is_dead() {
                buf.instrs[i] = Instr::DEAD;
                self.dead_count += 1;
                self.bytes_removed += INSTRUCTION_BYTES as u32;
            }
        }
    }

    fn mark(bitset: &mut [u64], idx: usize) {
        bitset[idx / 64] |= 1u64 << (idx % 64);
    }
    fn is_marked(bitset: &[u64], idx: usize) -> bool {
        bitset[idx / 64] & (1u64 << (idx % 64)) != 0
    }
}

// ─────────────────────────────────────────────
// PASS 3: LOOP UNROLLER
// Finds LOOP_BEGIN(count) ... LOOP_END patterns.
// Replicates the body `count` times (up to MAX_UNROLL_FACTOR),
// removes LOOP_BEGIN and LOOP_END overhead instructions.
// ─────────────────────────────────────────────

pub struct UnrollerPass {
    pub loops_unrolled: u32,
    pub instrs_added:   u32,
}

impl UnrollerPass {
    pub fn new() -> Self { Self { loops_unrolled: 0, instrs_added: 0 } }

    pub fn run(&mut self, buf: &mut IrBuffer) {
        let mut i = 0usize;
        while i < buf.len {
            if buf.instrs[i].opcode != 0x07 { i += 1; continue; } // LOOP_BEGIN
            let trip_count = (buf.instrs[i].a as usize).min(MAX_UNROLL_FACTOR);
            if trip_count < 2 { i += 1; continue; }

            // Find matching LOOP_END
            let loop_start = i + 1; // first instruction of body
            let loop_end   = match self.find_loop_end(buf, i) {
                Some(e) => e,
                None => { i += 1; continue; }
            };
            let body_len = loop_end - loop_start;
            if body_len == 0 || body_len * trip_count + buf.len > MAX_IR_INSTRUCTIONS {
                i += 1; continue;
            }

            // Capture body
            let mut body = [Instr::NOP; 256];
            let capture = body_len.min(256);
            for k in 0..capture { body[k] = buf.instrs[loop_start + k]; }

            // NOP-out LOOP_BEGIN and LOOP_END
            buf.instrs[i]        = Instr::NOP;
            buf.instrs[loop_end] = Instr::NOP;

            // Insert (trip_count - 1) additional copies of body after loop_end
            let insert_at = loop_end + 1;
            let extra = body_len * (trip_count - 1);
            // Shift tail rightward
            let tail = buf.len.saturating_sub(insert_at);
            for k in (0..tail).rev() {
                let src = insert_at + k;
                let dst = src + extra;
                if dst < MAX_IR_INSTRUCTIONS { buf.instrs[dst] = buf.instrs[src]; }
            }
            // Write extra copies
            for copy in 1..trip_count {
                for k in 0..body_len {
                    let dst = insert_at + (copy - 1) * body_len + k;
                    if dst < MAX_IR_INSTRUCTIONS { buf.instrs[dst] = body[k]; }
                }
            }
            buf.len = (buf.len + extra).min(MAX_IR_INSTRUCTIONS);
            self.loops_unrolled += 1;
            self.instrs_added   += (extra) as u32;
            i = loop_end + 1 + extra; // skip past unrolled body
        }
    }

    fn find_loop_end(&self, buf: &IrBuffer, begin_idx: usize) -> Option<usize> {
        let mut depth = 1u32;
        for j in (begin_idx + 1)..buf.len {
            match buf.instrs[j].opcode {
                0x07 => depth += 1,
                0x08 => {
                    depth -= 1;
                    if depth == 0 { return Some(j); }
                }
                _ => {}
            }
        }
        None
    }
}

// ─────────────────────────────────────────────
// CRUCIBLE ENGINE — orchestrates all passes
// ─────────────────────────────────────────────

pub struct CrucibleEngine {
    pub inliner:  InlinerPass,
    pub dce:      DcePass,
    pub unroller: UnrollerPass,
}

impl CrucibleEngine {
    pub fn new() -> Self {
        Self { inliner: InlinerPass::new(), dce: DcePass::new(), unroller: UnrollerPass::new() }
    }

    /// Apply mutation passes according to OptimizationFocus.
    /// Reads IR bytes from `input`, writes mutated IR bytes to `output`.
    /// Returns number of bytes written.
    pub fn mutate(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        focus: OptimizationFocus,
        fn_table: &FunctionTable,
        body_buf: &[Instr; MAX_IR_INSTRUCTIONS],
    ) -> usize {
        let mut buf = IrBuffer::decode_from(input);

        match focus {
            OptimizationFocus::MaximumThroughput => {
                // Full pipeline: inline → unroll → DCE
                self.inliner.run(&mut buf, body_buf, fn_table);
                self.unroller.run(&mut buf);
                self.dce.run(&mut buf);
            }
            OptimizationFocus::ThermalEfficiency => {
                // Minimal: DCE only (smaller code = less instruction fetch energy)
                self.dce.run(&mut buf);
            }
            OptimizationFocus::MemoryCompression => {
                // DCE + compact: remove DEAD/NOP instructions entirely (repack)
                self.dce.run(&mut buf);
                self.compact(&mut buf);
            }
        }

        buf.encode_to(output)
    }

    /// Compact: remove all DEAD and NOP instructions, repack the buffer
    fn compact(&self, buf: &mut IrBuffer) {
        let mut write = 0usize;
        for read in 0..buf.len {
            let instr = buf.instrs[read];
            if !instr.is_dead() && !instr.is_nop() {
                buf.instrs[write] = instr;
                write += 1;
            }
        }
        buf.len = write;
    }

    pub fn stats(&self) -> CrucibleStats {
        CrucibleStats {
            sites_inlined:  self.inliner.sites_inlined,
            loops_unrolled: self.unroller.loops_unrolled,
            dead_removed:   self.dce.dead_count,
            bytes_saved:    self.dce.bytes_removed + self.inliner.bytes_saved,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CrucibleStats {
    pub sites_inlined:  u32,
    pub loops_unrolled: u32,
    pub dead_removed:   u32,
    pub bytes_saved:    u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dce_removes_code_after_unconditional_ret() {
        // Build: RET, NOP, NOP (second and third are unreachable)
        let mut buf = IrBuffer::new();
        buf.instrs[0] = Instr { opcode: 0x06, a: 0, b: 0, flags: 0 }; // RET
        buf.instrs[1] = Instr::NOP;
        buf.instrs[2] = Instr::NOP;
        buf.len = 3;

        let mut dce = DcePass::new();
        dce.run(&mut buf);

        assert_eq!(buf.instrs[1].opcode, 0xFF); // marked DEAD
        assert_eq!(buf.instrs[2].opcode, 0xFF);
        assert_eq!(dce.dead_count, 2);
    }

    #[test]
    fn unroller_replicates_loop_body() {
        let mut buf = IrBuffer::new();
        // LOOP_BEGIN count=2, MOV, LOOP_END
        buf.instrs[0] = Instr { opcode: 0x07, a: 2, b: 0, flags: 0 };
        buf.instrs[1] = Instr { opcode: 0x01, a: 1, b: 2, flags: 0 }; // MOV r1, r2
        buf.instrs[2] = Instr { opcode: 0x08, a: 0, b: 0, flags: 0 }; // LOOP_END
        buf.len = 3;

        let mut unroller = UnrollerPass::new();
        unroller.run(&mut buf);
        assert_eq!(unroller.loops_unrolled, 1);
        // Should now have: NOP, MOV, NOP, MOV (unrolled copy)
        assert_eq!(buf.instrs[1].opcode, 0x01);
        assert_eq!(buf.instrs[3].opcode, 0x01);
    }
}
