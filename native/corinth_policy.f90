module corinth_policy
  use, intrinsic :: iso_c_binding, only: c_bool, c_double, c_int
  implicit none
contains
  function arach_corinth_build_score(features, count) result(score) bind(C)
    real(c_double), intent(in) :: features(*)
    integer(c_int), value, intent(in) :: count
    real(c_double) :: score
    real(c_double) :: reproducible, source_cached, dependency_cached, thermal

    if (count < 4_c_int) then
      score = 0.0_c_double
      return
    end if
    reproducible = max(0.0_c_double, min(1.0_c_double, features(1)))
    source_cached = max(0.0_c_double, min(1.0_c_double, features(2)))
    dependency_cached = max(0.0_c_double, min(1.0_c_double, features(3)))
    thermal = max(0.0_c_double, min(1.0_c_double, features(4)))
    score = reproducible * 0.50_c_double + source_cached * 0.20_c_double &
      + dependency_cached * 0.20_c_double - thermal * 0.20_c_double
    score = max(0.0_c_double, min(1.0_c_double, score))
  end function arach_corinth_build_score

  function arach_corinth_generation_ready(canonical, parent_matches, &
                                           file_synced, directory_synced) &
      result(ready) bind(C)
    logical(c_bool), value :: canonical
    logical(c_bool), value :: parent_matches
    logical(c_bool), value :: file_synced
    logical(c_bool), value :: directory_synced
    logical(c_bool) :: ready

    ready = canonical .and. parent_matches .and. file_synced .and. directory_synced
  end function arach_corinth_generation_ready
end module corinth_policy
