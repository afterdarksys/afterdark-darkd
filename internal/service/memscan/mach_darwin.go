//go:build darwin && cgo

package memscan

/*
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
static kern_return_t ads_task(int pid, mach_port_t *task) {
 if (pid == getpid()) { *task = mach_task_self(); return KERN_SUCCESS; }
 return task_for_pid(mach_task_self(), pid, task);
}
static void ads_release(int pid, mach_port_t task) {
 if (pid != getpid()) mach_port_deallocate(mach_task_self(), task);
}
static kern_return_t ads_region(mach_port_t task, mach_vm_address_t *addr,
 mach_vm_size_t *size, vm_prot_t *protection) {
 vm_region_basic_info_data_64_t info;
 mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
 mach_port_t object = MACH_PORT_NULL;
 kern_return_t result = mach_vm_region(task, addr, size, VM_REGION_BASIC_INFO_64,
   (vm_region_info_t)&info, &count, &object);
 if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
 if (result == KERN_SUCCESS) *protection = info.protection;
 return result;
}
*/
import "C"

import (
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"unsafe"
)

func darwinRead(pid int, address, size uint64) ([]byte, error) {
	if pid <= 0 || size == 0 || size > 64<<20 || address+size < address {
		return nil, fmt.Errorf("invalid memory read (maximum 64 MiB)")
	}
	var task C.mach_port_t
	if result := C.ads_task(C.int(pid), &task); result != C.KERN_SUCCESS {
		return nil, fmt.Errorf("task access denied: Mach %d (debug entitlement and OS authorization required)", result)
	}
	defer C.ads_release(C.int(pid), task)
	data := make([]byte, int(size))
	var read C.mach_vm_size_t
	result := C.mach_vm_read_overwrite(task, C.mach_vm_address_t(address), C.mach_vm_size_t(size), C.mach_vm_address_t(uintptr(unsafe.Pointer(&data[0]))), &read)
	if result != C.KERN_SUCCESS {
		return nil, fmt.Errorf("memory read failed: Mach %d", result)
	}
	if uint64(read) != size {
		return nil, fmt.Errorf("partial memory read: %d of %d", read, size)
	}
	return data, nil
}

func darwinRegions(pid int) ([]models.MemoryRegion, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid PID")
	}
	var task C.mach_port_t
	if result := C.ads_task(C.int(pid), &task); result != C.KERN_SUCCESS {
		return nil, fmt.Errorf("task access denied: Mach %d", result)
	}
	defer C.ads_release(C.int(pid), task)
	var address C.mach_vm_address_t
	regions := make([]models.MemoryRegion, 0)
	for len(regions) < 65536 {
		var size C.mach_vm_size_t
		var protection C.vm_prot_t
		result := C.ads_region(task, &address, &size, &protection)
		if result == C.KERN_INVALID_ADDRESS {
			return regions, nil
		}
		if result != C.KERN_SUCCESS {
			return nil, fmt.Errorf("memory regions failed: Mach %d", result)
		}
		perms := ""
		if protection&C.VM_PROT_READ != 0 {
			perms += "R"
		}
		if protection&C.VM_PROT_WRITE != 0 {
			perms += "W"
		}
		if protection&C.VM_PROT_EXECUTE != 0 {
			perms += "X"
		}
		regions = append(regions, models.MemoryRegion{BaseAddress: uint64(address), Size: uint64(size), Protection: perms, Type: "Unknown", State: "Commit", IsExecutable: protection&C.VM_PROT_EXECUTE != 0, IsWritable: protection&C.VM_PROT_WRITE != 0})
		next := uint64(address) + uint64(size)
		if size == 0 || next <= uint64(address) {
			return nil, fmt.Errorf("invalid memory region range")
		}
		address = C.mach_vm_address_t(next)
	}
	return nil, fmt.Errorf("memory region limit exceeded")
}
