package main

import (
	"syscall"
	"testing"
	"unsafe"
)

// TestHostEndianness checks the memory layout of the host machine.
func TestHostEndianness(t *testing.T) {
	var num uint16 = 0x0102
	lowestByteInMemory := *(*byte)(unsafe.Pointer(&num))

	switch lowestByteInMemory {
	case 0x02:
		t.Log("Host architecture is Little-Endian (expected for x86_64 and modern ARM)")
	case 0x01:
		t.Log("Host architecture is Big-Endian")
	default:
		t.Fatalf("Unexpected byte order detected: 0x%02x", lowestByteInMemory)
	}
}

// TestHostToNetwork16 verifies that hostToNetwork16 converts values correctly to Big-Endian.
// Fails on Big-Endian machines.
func TestHostToNetwork16(t *testing.T) {
	// Standard Linux ETH_P_ALL constant: 0x0003, encoded as [0x03, 0x00] in Little-Endian
	val := uint16(syscall.ETH_P_ALL)
	swappedBytes := hostToNetwork16(val)

	// In Big-Endian byte representation, 0x0003 is [0x00, 0x03]
	bigEndianBytes := [2]byte{0x00, 0x03}

	// In memory on the host, network order (Big-Endian) must ALWAYS place
	// high-order byte first: 0x00, followed by 0x03.
	actualBytesInMemory := *(*[2]byte)(unsafe.Pointer(&swappedBytes))
	if actualBytesInMemory != bigEndianBytes {
		t.Errorf("hostToNetwork16(0x%04x) placed %v in memory, expected %v",
			val, actualBytesInMemory, bigEndianBytes)
	}

	// Involutive property (applying swap twice restores original value)
	if hostToNetwork16(swappedBytes) != val {
		t.Errorf("Double swap failed: got 0x%04x, expected original 0x%04x",
			hostToNetwork16(swappedBytes), val)
	}
}
