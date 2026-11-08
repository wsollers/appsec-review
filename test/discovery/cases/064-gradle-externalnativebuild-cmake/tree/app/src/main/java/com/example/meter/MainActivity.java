package com.example.meter;

import android.app.Activity;
import android.os.Bundle;

public class MainActivity extends Activity {
    static { System.loadLibrary("meter"); }

    public static native int sampleCount();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle("samples: " + sampleCount());
    }
}
