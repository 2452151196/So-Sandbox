package com.example.anative;

import android.app.Application;
import android.content.SharedPreferences;

import androidx.appcompat.app.AppCompatDelegate;

import com.example.anative.ui.CrashHandler;

public class HookApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        restoreNightMode();
        CrashHandler.init(this);
    }

    private void restoreNightMode() {
        SharedPreferences prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);
        int savedMode = prefs.getInt("night_mode", -1);
        if (savedMode != -1 && savedMode != AppCompatDelegate.getDefaultNightMode()) {
            AppCompatDelegate.setDefaultNightMode(savedMode);
        }
    }
}
