//@author ComplexPlane
//@description Imports symbols provided in a map file exported by IDA. Nice for when you're using the free version that can't use the Ghidra XML exporter.
//@category SMB
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.XmlExporter;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.exception.*;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ImportIDAMap extends GhidraScript {

	private static final String IMPORT_ACTION = "Import map (add new symbols and rename existing symbols)";
	private static final String CLEAR_ACTION = "Delete symbols at addresses in map";

	@Override
	protected void run() throws Exception {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Namespace globalNs = currentProgram.getGlobalNamespace();

		BufferedReader mapFile = new BufferedReader(new FileReader(askFile("Select an IDA symbol map to import. Note that this will overwrite existing symbols at the given addresses.", "Import")));
		String line;

		// Select action
		List<String> actions = new ArrayList<>(Arrays.asList(IMPORT_ACTION, CLEAR_ACTION));
		String action = askChoice("Choose Action", "Choose action", actions, IMPORT_ACTION);

		Pattern linePattern = Pattern.compile("([0-9a-fA-F]{8}):([0-9a-fA-F]{16})       (.+)");
		Pattern cppNamePattern = Pattern.compile(".+\\(.*\\).*");
		Pattern strNamePattern = Pattern.compile("a.*");
		Pattern cNamePattern = Pattern.compile("_(.+)");

		MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();

		HashSet<Address> strAddrSet = new HashSet<>();
		for (Data data : DefinedDataIterator.definedStrings(currentProgram)) {
			strAddrSet.add(data.getAddress());
		}

		while ((line = mapFile.readLine()) != null) {
			line = line.strip();
			Matcher lineMatcher = linePattern.matcher(line);
			if (!lineMatcher.matches()) {
				continue;
			}

			int section = Integer.parseInt(lineMatcher.group(1), 16);
			long offset = Long.parseLong(lineMatcher.group(2), 16);
			String name = lineMatcher.group(3);

			if (name.startsWith("def_") || name.startsWith("jpt_")) continue;

			Address addr = blocks[section].getStart().add(offset);

			if (cppNamePattern.matcher(name).matches()) {
				// Label cpp symbols
//				printf("C++ name: 0x%s %s\n", addr.toString(), name);
				addSymbol(name, addr, action);
			} else if (strNamePattern.matcher(name).matches()) {
				// Create ascii string if not already there
//				printf("ASCII string: 0x%s %s\n", addr.toString(), name);
				try {
					createAsciiString(addr);
				} catch (Exception e) {
					printerr(String.format("Could not create string: 0x%s %s\n", addr.toString(), name));
				}
			} else {
				Matcher cNameMatcher = cNamePattern.matcher(name);
				if (cNameMatcher.matches()) {
//					printf("C name: 0x%s %s\n", addr.toString(), cNameMatcher.group(1));
					addSymbol(cNameMatcher.group(1), addr, action);
				} else {
//					printf("Unknown symbol type: 0x%s %s\n", addr.toString(), name);
					addSymbol(name, addr, action);
				}
			}
		}

		popup("It's recommended to re-analyze this file when you're ready");
	}

	private void addSymbol(String name, Address addr, String action) {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Symbol[] userSymbols = symbolTable.getUserSymbols(addr);

		if (action.equals(IMPORT_ACTION)) {
			if (userSymbols.length == 0) {
				try {
					symbolTable.createLabel(addr, name, SourceType.IMPORTED);
				} catch (InvalidInputException e) {
					printf("Failed to create symbol: 0x%s %s\n", addr.toString(), name);
//					e.printStackTrace();
				}
			} else {
				for (Symbol s : userSymbols) {
					if (!s.getName().equals(name)) {
						try {
							s.setName(name, SourceType.IMPORTED);
						} catch (InvalidInputException | DuplicateNameException e) {
							printf("Failed to create symbol: 0x%s %s\n", addr.toString(), name);
//							e.printStackTrace();
						}
					}
				}
			}

		} else if (action.equals(CLEAR_ACTION)) {
			// Remove existing symbols at the address of this symbol
			for (Symbol s : userSymbols) {
				symbolTable.removeSymbolSpecial(s);
			}

		}
	}
}
