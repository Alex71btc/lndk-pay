package com.bolt12pay.companion;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.AtomicFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

final class ServerSettings {
    private static final String PREFS_NAME = "bolt12_pay_companion";
    private static final String PREF_SERVER_URL = "server_url";
    private static final String BACKUP_FILE_NAME = "server-url-v1";

    private final SharedPreferences preferences;
    private final AtomicFile backupFile;

    ServerSettings(Context context) {
        preferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        backupFile = new AtomicFile(new File(context.getFilesDir(), BACKUP_FILE_NAME));
    }

    String load() {
        String preferred =
                ServerUrl.normalize(preferences.getString(PREF_SERVER_URL, ""));
        if (preferred != null) {
            writeBackup(preferred);
            return preferred;
        }

        String recovered = readBackup();
        if (recovered != null) {
            preferences.edit().putString(PREF_SERVER_URL, recovered).commit();
        }
        return recovered;
    }

    boolean save(String serverUrl) {
        String normalized = ServerUrl.normalize(serverUrl);
        if (normalized == null) return false;

        boolean preferencesSaved =
                preferences.edit().putString(PREF_SERVER_URL, normalized).commit();
        boolean backupSaved = writeBackup(normalized);
        return preferencesSaved || backupSaved;
    }

    private String readBackup() {
        try {
            return ServerUrl.normalize(
                    new String(backupFile.readFully(), StandardCharsets.UTF_8));
        } catch (IOException error) {
            return null;
        }
    }

    private boolean writeBackup(String serverUrl) {
        FileOutputStream output = null;
        try {
            output = backupFile.startWrite();
            output.write(serverUrl.getBytes(StandardCharsets.UTF_8));
            backupFile.finishWrite(output);
            return true;
        } catch (IOException error) {
            if (output != null) backupFile.failWrite(output);
            return false;
        }
    }
}
