peb - get current process peb
!peb - get latest process event peb 
!peb %p - get peb of specific Handle

!pi - get latest process event process info
!pi pid - get process info of specific process

!pe - get pe header of current process
!pe %p - get pe header of specific process


!ti - get thread info of latest thread event
!ti %p - get thread info of specific thread using base address

!teb %p - get teb of latest thread event
!teb %p - get teb of specific thread

!iat %p - get IAT of specific thread ( using rva )

g - continue
t - step in
reg - print current thread regs
db %p - read memory 

exit - disconnect debugger
