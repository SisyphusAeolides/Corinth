#!/usr/bin/env python3
from pathlib import Path


# Retained for the previously reviewed branch gate's byte-string guard.
_MARKERS = [
    """        output.extend_from_slice(if source.submodules {""",
    """        output.extend_from_slice(if source.submodules {""",
]


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}")
    target.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    "src/hardware.rs",
    """        let source_dir = self.materialize_sources(&recipe.source, &source_lock)?;
        if recipe.build.system == "cosmic" {
            run_cosmic_workspace(&source_dir, recipe.policy.network)?;
        } else if recipe.build.system == "arach-kernel" {
            run_arach_kernel_workspace(&source_dir, recipe.policy.network)?;
        } else {
""",
    """        let materialized_sources = kernel_materialization_sources(&recipe)?;
        let source_dir = self.materialize_sources(&materialized_sources, &source_lock)?;
        if recipe.build.system == "cosmic" {
            run_cosmic_workspace(&source_dir, recipe.policy.network)?;
        } else if is_fixed_kernel_recipe(&recipe) {
            run_arach_kernel_workspace(&source_dir, recipe.policy.network)?;
        } else {
""",
)

replace_once(
    "src/hardware.rs",
    """    } else if recipe.build.system == "arach-kernel" {
        let primary = recipe
            .source
            .iter()
            .filter(|source| source.destination.is_none())
            .count();
        let push = recipe
            .source
            .iter()
            .filter(|source| source.destination.as_deref() == Some("sources/push"))
            .count();
        if recipe.policy.network
            || recipe.source.len() != 2
            || primary != 1
            || push != 1
            || recipe.build.commands != ["cargo build-kernel-package"]
            || recipe.build.outputs.as_slice()
                != ["target/package-kernel/x86_64-arach/release/arach"]
        {
            return Err(HardwareError::InvalidRecipe(
                "Arach kernel recipes must use the fixed offline kernel adapter".into(),
            ));
        }
    } else {
""",
    """    } else if is_fixed_kernel_recipe(recipe) {
        if recipe.policy.network
            || recipe.build.commands != ["cargo build-kernel-package"]
            || recipe.build.outputs.as_slice()
                != ["target/package-kernel/x86_64-arach/release/arach"]
        {
            return Err(HardwareError::InvalidRecipe(
                "Arach kernel recipes must use the fixed offline kernel adapter".into(),
            ));
        }
    } else if recipe.package.name == "arach-kernel" || recipe.build.system == "arach-kernel" {
        return Err(HardwareError::InvalidRecipe(
            "Arach kernel recipe does not match the fixed adapter contract".into(),
        ));
    } else {
""",
)

replace_once(
    "src/hardware.rs",
    """fn validate_recipe(
""",
    """const ARACH_KERNEL_REPOSITORY: &str =
    "https://github.com/SisyphusAeolides/Arach-Kernel.git";
const ARACH_PUSH_REPOSITORY: &str = "https://github.com/SisyphusAeolides/Push.git";

fn is_fixed_kernel_recipe(recipe: &RecipeDocument) -> bool {
    if recipe.package.name != "arach-kernel" || recipe.source.len() != 2 {
        return false;
    }
    let kernel = &recipe.source[0];
    let push = &recipe.source[1];
    let ordered_sources = kernel.kind == "git"
        && kernel.url.as_deref() == Some(ARACH_KERNEL_REPOSITORY)
        && push.kind == "git"
        && push.url.as_deref() == Some(ARACH_PUSH_REPOSITORY);
    if !ordered_sources {
        return false;
    }
    match recipe.build.system.as_str() {
        "arach-kernel" => {
            kernel.destination.is_none()
                && push.destination.as_deref() == Some("sources/push")
        }
        "custom" => kernel.destination.is_none() && push.destination.is_none(),
        _ => false,
    }
}

fn kernel_materialization_sources(
    recipe: &RecipeDocument,
) -> Result<Vec<RecipeSource>, HardwareError> {
    if !is_fixed_kernel_recipe(recipe) {
        return Ok(recipe.source.clone());
    }
    let mut sources = recipe.source.clone();
    if recipe.build.system == "custom" {
        sources[1].destination = Some("sources/push".into());
    }
    Ok(sources)
}

fn validate_recipe(
""",
)

replace_once(
    "src/hardware.rs",
    """        changed.submodules = true;
        assert_ne!(first, source_lock_digest(&[changed]));
""",
    """        changed.submodules = true;
        assert_ne!(first, source_lock_digest(&[changed]));
""",
)
