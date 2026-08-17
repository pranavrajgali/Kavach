package com.android.system;

import android.app.Activity;
import android.os.Bundle;
import android.telephony.TelephonyManager;

/** Positive value-taint and negative key-only-taint calls share the real helper signature. */
public final class PersistenceActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        TelephonyManager manager = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        String sensitive = manager.getDeviceId();
        IO storage = new IO();
        storage.writeConfig("BotID", sensitive, this);
        storage.writeConfig(sensitive, "clean", this);
    }
}
