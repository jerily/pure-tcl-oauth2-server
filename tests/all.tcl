package require tcltest 2
set root [file dirname [file dirname [file normalize [info script]]]]
lappend auto_path $root
::tcltest::configure -testdir [file dirname [info script]] -singleproc true {*}$argv
exit [::tcltest::runAllTests]
