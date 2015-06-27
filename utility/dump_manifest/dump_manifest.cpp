/*--

	Copyright (c) 2015 YoungJin Shin <codewiz@wellbia.com>

	Abstract:

		Manifest Dump Utility

	Module:
	
		dump_manifest.cpp

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>

--*/

#include <windows.h>
#include <vector>
#include <strsafe.h>

#define GetOffset(dst, src) ((ULONG_PTR) (dst) - (ULONG_PTR) (src))
#define GetPtr(b, o) ((PVOID)(((ULONG_PTR) b + (ULONG_PTR) o)))
#define GetSectionHeaderFromNT(nt) ((PIMAGE_SECTION_HEADER) GetPtr(&nt->OptionalHeader, nt->FileHeader.SizeOfOptionalHeader))

typedef std::vector<UCHAR> ByteBuffer;
typedef std::vector<CHAR> CharBuffer;

BOOL
GetManifestStringFromModule(HMODULE mod, LPSTR manifest, SIZE_T size)
{
	HRSRC rsrc = FindResourceW(mod, MAKEINTRESOURCE(1), RT_MANIFEST);
	if(!rsrc)
		return FALSE;

	ULONG rsrc_size = SizeofResource(mod, rsrc);

	HGLOBAL grsrc = LoadResource(mod, rsrc);
	if(!grsrc)
		return FALSE;

	PVOID prsrc = LockResource(grsrc);
	if(!prsrc)
	{
		FreeResource(grsrc);
		return FALSE;
	}

	ByteBuffer tmp;
	tmp.resize(rsrc_size);
	memcpy(&tmp[0], prsrc, rsrc_size);
	tmp.push_back(0);

	StringCbCopyA(manifest, size, (LPCSTR) &tmp[0]);

	UnlockResource(prsrc);
	FreeResource(grsrc);
	return TRUE;

}

PIMAGE_NT_HEADERS32 
GetNTHeaders32(LPCVOID p, SIZE_T size)
{
	try
	{
		PIMAGE_NT_HEADERS32 nt;
		PIMAGE_DOS_HEADER dos;

		if(size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
			return NULL;
		
		dos = (PIMAGE_DOS_HEADER) p;
		if(dos->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		if(dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size)
			return NULL;

		nt = (PIMAGE_NT_HEADERS32) GetPtr(dos, dos->e_lfanew);
		if(nt->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		if(nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			return NULL;

		return nt;
	}
	catch(...)
	{
	}

	return NULL;
}

PIMAGE_NT_HEADERS64
GetNTHeaders64(LPCVOID p, SIZE_T size)
{
	try
	{
		PIMAGE_NT_HEADERS64 nt;
		PIMAGE_DOS_HEADER dos;

		if(size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
			return NULL;
		
		dos = (PIMAGE_DOS_HEADER) p;
		if(dos->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		if(dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size)
			return NULL;

		nt = (PIMAGE_NT_HEADERS64) GetPtr(dos, dos->e_lfanew);
		if(nt->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		if(nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			return NULL;

		return nt;
	}
	catch(...)
	{
	}

	return NULL;
}

PIMAGE_RESOURCE_DIRECTORY_ENTRY
FindResourceDirectoryEntryWithName(PVOID root, PIMAGE_RESOURCE_DIRECTORY rd, LPCWSTR name)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY entry;
	entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) GetPtr(rd, sizeof(*rd));

	ULONG cnt = rd->NumberOfNamedEntries + rd->NumberOfIdEntries;

	for(ULONG i = 0; i < cnt; ++i)
	{
		if(entry[i].NameIsString)
		{
			PIMAGE_RESOURCE_DIR_STRING_U rname;
			rname = (PIMAGE_RESOURCE_DIR_STRING_U) GetPtr(root, entry[i].NameOffset);

			WCHAR tmp[MAX_PATH];
			StringCbCopyNW(tmp, sizeof(tmp), rname->NameString, rname->Length);

			if(wcscmp(tmp, name) == 0)
				return &entry[i]; 
		}
	}

	return NULL;
}

PIMAGE_RESOURCE_DIRECTORY_ENTRY
FindResourceDirectoryEntryWithId(PVOID root, PIMAGE_RESOURCE_DIRECTORY rd, USHORT id)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY entry;
	entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) GetPtr(rd, sizeof(*rd));

	ULONG cnt = rd->NumberOfNamedEntries + rd->NumberOfIdEntries;

	for(ULONG i = 0; i < cnt; ++i)
	{
		if(!entry[i].NameIsString)
		{
			if(id == entry[i].Id)
				return &entry[i]; 
		}
	}

	return NULL;
}

BOOL
GetManifestStringFromBuffer(LPCVOID abuffer
								, SIZE_T buffer_size
								, LPSTR manifest
								, SIZE_T manifest_size
								, PSIZE_T required_size)
{
	ULONG sec_cnt = 0;
	PIMAGE_SECTION_HEADER sec = NULL;
	PIMAGE_DATA_DIRECTORY dd = NULL;
	PUCHAR buffer = (PUCHAR) abuffer;

	PIMAGE_NT_HEADERS32 nt32 = GetNTHeaders32(buffer, buffer_size);
	if(nt32)
	{
		sec_cnt = nt32->FileHeader.NumberOfSections;
		sec = GetSectionHeaderFromNT(nt32);
		dd = &nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	}
	else
	{
		PIMAGE_NT_HEADERS64 nt64 = GetNTHeaders64(buffer, buffer_size);
		if(nt64)
		{
			sec_cnt = nt64->FileHeader.NumberOfSections;
			sec = GetSectionHeaderFromNT(nt64);
			dd = &nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
		}
	}

	if(!sec || !dd)
		return FALSE;

	PVOID rptr = GetPtr(buffer, dd->VirtualAddress);

	for(ULONG i = 0; i < sec_cnt; ++i)
	{
		PVOID sptr = GetPtr(buffer, sec[i].VirtualAddress);
		PVOID eptr = GetPtr(sptr, sec[i].Misc.VirtualSize);

		if(rptr >= sptr && rptr < eptr)
		{
			PIMAGE_RESOURCE_DIRECTORY root;
			
			ULONG diff = GetOffset(sptr, rptr);
			root = (PIMAGE_RESOURCE_DIRECTORY) &buffer[sec[i].PointerToRawData + diff];

			PIMAGE_RESOURCE_DIRECTORY_ENTRY entry;
			entry = FindResourceDirectoryEntryWithId(root, root, (ULONG_PTR) RT_MANIFEST);
			if(!entry)
				return FALSE;

			PIMAGE_RESOURCE_DIRECTORY rd;
			rd = (PIMAGE_RESOURCE_DIRECTORY) GetPtr(root, entry->OffsetToDirectory);
			entry = FindResourceDirectoryEntryWithId(root, rd, 1);
			if(!entry)
				return FALSE;

			rd = (PIMAGE_RESOURCE_DIRECTORY) GetPtr(root, entry->OffsetToDirectory);
			entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) GetPtr(rd, sizeof(*rd));

			PIMAGE_RESOURCE_DATA_ENTRY data;
			data = (PIMAGE_RESOURCE_DATA_ENTRY) GetPtr(root, entry->OffsetToData);

			PVOID pdata = GetPtr(root, data->OffsetToData - sec[i].VirtualAddress + diff);

			if(required_size)
				*required_size = data->Size + 1;

			if(manifest_size < data->Size + 1)
			{
				SetLastError(ERROR_INSUFFICIENT_BUFFER);
				return FALSE;
			}

			memcpy(manifest, pdata, data->Size);
			manifest[data->Size] = '\0';
			return TRUE;
		}
	}

	return FALSE;
}


int main(int argc, char *argv[])
{
	if(argc < 2)
		return -1;

	FILE *fp;

	fp = fopen(argv[1], "rb");
	if(!fp)
		return -1;

	fseek(fp, 0l, SEEK_END);
	long file_size = ftell(fp);
	if(!file_size)
	{
		fclose(fp);
		return -2;
	}

	ByteBuffer buffer;
	buffer.resize(file_size);

	fseek(fp, 0l, SEEK_SET);
	if(fread(&buffer[0], 1, buffer.size(), fp) != buffer.size())
	{
		fclose(fp);
		return -3;
	}

	SIZE_T required = 0;
	if(!GetManifestStringFromBuffer(&buffer[0], buffer.size(), NULL, 0, &required))
	{
		if(GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return -5;
	}

	CharBuffer manifest;
	manifest.resize(required);

	if(!GetManifestStringFromBuffer(&buffer[0], buffer.size(), &manifest[0], manifest.size(), &required))
		return -6;

	printf("%s\n", &manifest[0]);
	return 0;
}
