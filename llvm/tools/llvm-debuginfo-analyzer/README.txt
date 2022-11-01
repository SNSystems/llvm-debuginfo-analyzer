//===- llvm/tools/llvm-debuginfo-analyzer/README.txt ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains notes collected during the development, review and test.
// It describes limitations, know issues and future work.
//
//===----------------------------------------------------------------------===//

//===---------------------------------------------------------------------===//

- Change command line options to use tablegen.
https://reviews.llvm.org/D125777#inline-1291801

//===---------------------------------------------------------------------===//

- Use smart pointers.
https://reviews.llvm.org/D125778#inline-1210290
https://reviews.llvm.org/D125778#inline-1210381
https://reviews.llvm.org/D125778#inline-1291984

//===---------------------------------------------------------------------===//

# Future work
--------------------------------------------------------------------------------
- Pass references instead of pointers (Comparison functions).

- Use StringMap for LVSymbolNames.

- Support for '-ffunction-sections'.

- Add support for DWARF v5 .debug_names section.

- Add support for CodeView public symbols stream.
  Currently similar data is collected during debug info parsing.

- LVDoubleMap to return optional<ValueType> instead of null pointer.

- Refactor 'processLines'.

- Calculate unique offset for CodeView elements.
  To have the same functionality as the DWARF offset.
  // TODO: Use the 'PointerToRawData' as base for the unique offset for the
  // Symbol records. Using 'RecordOffset' does not give unique values
  // as that offset is relative to each subsection.
  //uint32_t PointerToRawData = 0;
  //#define ABSOLUTE_OFFSET(offset) (PointerToRawData + offset)
  //PointerToRawData = getObj().getCOFFSection(Section)->PointerToRawData;

- Move initializeFileAndStringTables to the COFF Library.

- Easy access to 'getSymbolKindName' and 'formatRegisterId' (SymbolDumper.cpp)
  At the moment we have to duplicate it.

- class LVDoubleMap
  Is the correct data structure?

- Rewrite ELFReaderTest and CodeViewReaderTest to eliminate the call:
  getInputFileDirectory()

- Use of std::unordered_set instead of std::set
  There is no based on comparison operations with DeducedScopes,
  UnresolvedScopes and IdentifiedNamespaces, the sets are used for
  searching only. It looks like the std::unordered_set with O(1)
  inserting/searching is enough (hm, maybe except the UnresolvedScopes
  variable because there is an iteration over the set and the order
  might be important).

-I think this loop could be replaced with something along the lines of
LVStringRefs::iterator Iter = std::find_if(Components.begin(), Components.end(), 
    [](StringRef Name) {
        return IdentifiedNamespaces.find(Name) == IdentifiedNamespaces.end();
    });
LVStringRefs::size_type FirstNonNamespace = std::distance(Components.begin(), Iter);

find_if returns an iterator into Components for the first non-namespace, and then std::distance gets the index.

//===---------------------------------------------------------------------===//
