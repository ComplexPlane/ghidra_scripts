//@author ComplexPlane
//@category SMB
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.CppExporter;
import ghidra.program.model.listing.*;
import java.io.File;
import java.io.FileWriter;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.Version;
import ghidra.app.util.Option;
import java.util.ArrayList;
import java.util.Arrays;

public class ExportGitRepo extends GhidraScript {

	@Override
	protected void run() throws Exception {
        DomainFolder projectFolder = getProjectRootFolder();
        DomainFile projectFile = projectFolder.getFile("mkb2.main_loop.rel");

        CppExporter exporter = new CppExporter();
        ArrayList<Option> exportOptions = new ArrayList<Option>(Arrays.asList(
            new Option(CppExporter.CREATE_C_FILE, true),
            new Option(CppExporter.CREATE_HEADER_FILE, true),
            new Option(CppExporter.USE_CPP_STYLE_COMMENTS, true)
        ));
        exporter.setOptions(exportOptions);

        File outDir = new File(projectFolder.getProjectLocator().getProjectDir(), "../ghidra2git");
        outDir.mkdirs();

        for (Version version : projectFile.getVersionHistory()) {
            File versionDir = new File(outDir, "v" + version.getVersion());

            File doneFile = new File(versionDir, "DONE");
            if (doneFile.exists()) {
                printf("Version %d already exported, skipping\n", version.getVersion());

            } else {
                printf("Exporting version %d\n", version.getVersion());

                versionDir.mkdirs();

                FileWriter commentFileWriter = new FileWriter(new File(versionDir, "COMMENT"));
                commentFileWriter.write(version.getComment());
                commentFileWriter.close();

                FileWriter versionFileWriter = new FileWriter(new File(versionDir, "VERSION"));
                versionFileWriter.write("" + version.getVersion());
                versionFileWriter.close();

                FileWriter timeFileWriter = new FileWriter(new File(versionDir, "TIME"));
                timeFileWriter.write("" + version.getCreateTime());
                timeFileWriter.close();

                FileWriter userFileWriter = new FileWriter(new File(versionDir, "USER"));
                userFileWriter.write(version.getUser());
                userFileWriter.close();

                DomainObject projectFileObj = projectFile.getReadOnlyDomainObject(this, version.getVersion(), null);
                File cFile = new File(versionDir, "mkb2.c");
                exporter.export(cFile, projectFileObj, null, monitor);
                projectFileObj.release(this);

                FileWriter doneFileWriter = new FileWriter(new File(versionDir, "DONE"));
                doneFileWriter.write("DONE");
                doneFileWriter.close();
            }
        }
	}
}
