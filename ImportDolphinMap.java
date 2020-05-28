//@author ComplexPlane
//@description Imports labels found by strand_match.
//@category SMB
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.XmlExporter;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.*;
import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

public class ImportDolphinMap extends GhidraScript {

	@Override
	protected void run() throws Exception {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Namespace globalNs = currentProgram.getGlobalNamespace();

		BufferedReader mapFile = new BufferedReader(new FileReader(askFile("Select a Dolphin symbol map to import.\nNote that this will overwrite existing symbols at the given addresses.", "Import")));
		String line;

		// Select action
		String importAction = "Import map (replacing existing symbols at conflicting addresses)";
		String renameAction = "Rename existing symbols using map";
		String clearAction = "Delete symbols at addresses in map";
		List<String> actions = new ArrayList<>(Arrays.asList(importAction, renameAction, clearAction));
		String action = askChoice("Choose Action", "Choose action", actions, importAction);

		while ((line = mapFile.readLine()) != null) {
			if (line.matches("^.+section layout$") || line.length() == 0) {
				continue;
			}

			String[] split = line.split(" ");
			Address addr = toAddr(split[0]);

			// Use namespace if provided
			String[] splitName = split[4].split("::", 2);
			Namespace ns;
			String newSymbolName;
			if (splitName.length == 2) {
				String nsName = splitName[0];
				newSymbolName = splitName[1];
				try {
					ns = symbolTable.createNameSpace(globalNs, nsName, SourceType.IMPORTED);
				} catch (DuplicateNameException e) {
					ns = symbolTable.getNamespace(nsName, globalNs);
				}
			} else { // splitName.length == 1
				ns = globalNs;
				newSymbolName = splitName[0];
			}

			Symbol[] userSymbols = symbolTable.getUserSymbols(addr);

			if (action.equals(importAction)) {
				// Remove existing symbols at the address of this symbol
				for (Symbol s : userSymbols) {
					symbolTable.removeSymbolSpecial(s);
				}

				// Create new IMPORTED label
				symbolTable.createLabel(addr, newSymbolName, ns, SourceType.IMPORTED);

				popup("It's recommended to re-analyze this file when you're ready");

			} else if (action.equals(renameAction)) {
				for (Symbol s : userSymbols) {
					s.setName(newSymbolName, s.getSource());
				}

			} else if (action.equals(clearAction)) {
				// Remove existing symbols at the address of this symbol
				for (Symbol s : userSymbols) {
					symbolTable.removeSymbolSpecial(s);
				}

				popup("It's recommended to re-analyze this file when you're ready");
			}
		}

	}
}
