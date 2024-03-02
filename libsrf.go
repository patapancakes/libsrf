package libsrf

import (
	"encoding/binary"
	"fmt"
	"os"
)

type SrfData struct {
	Resources map[string]SrfResource
}

type SrfResource struct {
	Id    string
	Items map[int][]byte
}

func DecodeSrfFile(file *os.File) (SrfData, error) {
	// magic
	magic := make([]byte, 4)
	_, err := file.ReadAt(magic, 0x00)
	if err != nil {
		return SrfData{}, fmt.Errorf("failed to read magic: %s", err)
	}
	if string(magic) != "srf1" {
		return SrfData{}, fmt.Errorf("invalid magic: expected \"srf1\", got \"%s\"", magic)
	}

	// file length
	fileLen := make([]byte, 4)
	_, err = file.ReadAt(fileLen, 0x04)
	if err != nil {
		return SrfData{}, fmt.Errorf("failed to read file length: %s", err)
	}

	// size check
	stat, err := file.Stat()
	if err != nil {
		return SrfData{}, fmt.Errorf("failed to stat file: %s", err)
	}
	if binary.BigEndian.Uint32(fileLen) != uint32(stat.Size()) {
		return SrfData{}, fmt.Errorf("file size is incorrect: expected %d, got %d", binary.BigEndian.Uint32(fileLen), stat.Size())
	}

	// header length
	headerLen := make([]byte, 4)
	_, err = file.ReadAt(headerLen, 0x08)
	if err != nil {
		return SrfData{}, fmt.Errorf("failed to read header length: %s", err)
	}

	srfData := SrfData{Resources: make(map[string]SrfResource)}

	// resource read loop
	lastResourceStartOffset := 0x0C
	for lastResourceStartOffset != 0x0C+int(binary.BigEndian.Uint32(headerLen)) {
		resourceId := make([]byte, 4)
		_, err = file.ReadAt(resourceId, int64(lastResourceStartOffset))
		if err != nil {
			return SrfData{}, fmt.Errorf("failed to read resource identifier: %s", err)
		}

		resourceItemsLen := make([]byte, 4)
		_, err = file.ReadAt(resourceItemsLen, int64(lastResourceStartOffset)+4)
		if err != nil {
			return SrfData{}, fmt.Errorf("failed to read resource items length: %s", err)
		}

		resource := SrfResource{Id: string(resourceId), Items: make(map[int][]byte)}

		for i := range binary.BigEndian.Uint32(resourceItemsLen) {
			resourceItemNum := make([]byte, 4)
			_, err = file.ReadAt(resourceItemNum, int64(lastResourceStartOffset+8+int(i*12)))
			if err != nil {
				return SrfData{}, fmt.Errorf("failed to read resource item number: %s", err)
			}

			resourceItemOffset := make([]byte, 4)
			_, err = file.ReadAt(resourceItemOffset, int64(lastResourceStartOffset+12+int(i*12)))
			if err != nil {
				return SrfData{}, fmt.Errorf("failed to read resource item offset: %s", err)
			}

			resourceItemSize := make([]byte, 4)
			_, err = file.ReadAt(resourceItemSize, int64(lastResourceStartOffset+16+int(i*12)))
			if err != nil {
				return SrfData{}, fmt.Errorf("failed to read resource item size: %s", err)
			}

			resourceItemData := make([]byte, binary.BigEndian.Uint32(resourceItemSize))
			_, err = file.ReadAt(resourceItemData, int64(binary.BigEndian.Uint32(resourceItemOffset)))
			if err != nil {
				return SrfData{}, fmt.Errorf("failed to read resource item: %s", err)
			}

			resource.Items[int(binary.BigEndian.Uint32(resourceItemNum))] = resourceItemData

			if i+1 == binary.BigEndian.Uint32(resourceItemsLen) {
				lastResourceStartOffset += 8 + (int(binary.BigEndian.Uint32(resourceItemsLen)) * 12)
			}
		}

		srfData.Resources[resource.Id] = resource
	}

	return srfData, nil
}
