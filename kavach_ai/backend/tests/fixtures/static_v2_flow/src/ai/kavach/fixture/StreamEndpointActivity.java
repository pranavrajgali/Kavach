package ai.kavach.fixture;

import android.app.Activity;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;

/** Positive and negative destination fixtures for DataOutputStream.writeBytes. */
public final class StreamEndpointActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TelephonyManager manager = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        String sensitive = manager.getDeviceId();
        network(sensitive);
        file(sensitive);
        unknown(sensitive, new ByteArrayOutputStream());
    }

    private void network(String value) {
        try {
            URLConnection connection = new URL("https://example.invalid/direct").openConnection();
            DataOutputStream output = new DataOutputStream(connection.getOutputStream());
            output.writeBytes(value);
        } catch (Exception ignored) { }
    }

    private void file(String value) {
        try {
            DataOutputStream output = new DataOutputStream(new FileOutputStream(getFilesDir() + "/local"));
            output.writeBytes(value);
        } catch (Exception ignored) { }
    }

    private void unknown(String value, OutputStream destination) {
        try {
            DataOutputStream output = new DataOutputStream(destination);
            output.writeBytes(value);
        } catch (Exception ignored) { }
    }
}
