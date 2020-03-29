//@author ComplexPlane
//@description Exports a map file which Dolphin can import. Only works on functions in main.dol and mainloop for now.
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
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

public class ExportApeSphereMap extends GhidraScript {

	@Override
	protected void run() throws Exception {
		PrintWriter mapFile = new PrintWriter(new FileWriter(askFile("ApeSpehre map file name", "Save")));

		Program prog = getCurrentProgram();
		Address endMainLoopAddr = toAddr(0x8054c8cc);

		for (Function func : prog.getFunctionManager().getFunctions(true)) {
			Address addr = func.getEntryPoint();
			if (endMainLoopAddr.subtract(addr) <= 0) continue;
			if (func.getSymbol().getSource() == SourceType.DEFAULT) continue;

			String addrStr = addr.toString();
			long size = func.getBody().getNumAddresses();
			String name = func.getName();

			mapFile.printf("%s:%s\n", addrStr, name);
		}

		mapFile.flush();
	}
}
