package com.android.system;

import android.content.Context;

/** Signature-compatible persistence helper boundary for parameter semantics. */
public final class IO {
    public void writeConfig(String key, String value, Context context) { }
    public String readConfig(String key, Context context) { return "stored"; }
}
