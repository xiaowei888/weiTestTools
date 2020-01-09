package com.example.activitydemo;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.hardware.Camera;
import android.os.Bundle;
import android.os.IBinder;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity {

    String buildType = "";
    Button bt_click;
    TextView tv_show;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        bt_click = findViewById(R.id.bt_click);
        tv_show = findViewById(R.id.tv_show);

        /*buildType = System.getProperties().getProperty("ro.build.type");
        Log.i("wei","into MainActivity onCreate buildType = " + buildType);
        IBinder binder = android.os.ServiceManager.getService("NvRAMAgent");
        NvRAMAgent agent = NvRAMAgent.Stub.asInterface(binder);
        if(agent == null){
            Log.i("wei","agent is null");
        }
        byte[] buff = null;
        try {
            buff = agent.readFile(36);// AP_CFG_REEB_PRODUCT_INFO_LID
            StringBuilder builder = new StringBuilder();

            Log.i("wei","buff:"+buff.toString());
        } catch (Exception ee) {     ee.printStackTrace();    }*/
    }

    @Override
    protected void onRestart() {
        Log.i("wei", "into MainActivity onRestart");

        super.onRestart();
    }

    @Override
    protected void onStop() {
        Log.i("wei", "into MainActivity onStop");
        super.onStop();
    }

    @Override
    protected void onDestroy() {
        Log.i("wei", "into MainActivity onDestroy");
        super.onDestroy();
    }

    @Override
    protected void onStart() {
        Log.i("wei", "into MainActivity onStart");
        super.onStart();
    }

    @Override
    protected void onResume() {
        Log.i("wei", "into MainActivity onResume");
        super.onResume();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        Log.i("wei", "into MainActivity onNewIntent");
        super.onNewIntent(intent);
    }
    boolean rootFlag = false;
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.bt_click:
                rootFlag = isRoot();
                tv_show.setText(String.valueOf(rootFlag));
                break;
        }
    }

    /**
     * 是否存在su命令，并且有执行权限
     *
     * @return 存在su命令，并且有执行权限返回true
     */
    public static boolean isRoot() {
        File file = null;
        String[] paths = {"/system/bin/", "/system/xbin/", "/system/sbin/", "/sbin/", "/vendor/bin/", "/su/bin/"};
        try {
            for (String path : paths) {
                file = new File(path + "su");
                if (file.exists() /*&& file.canExecute()*/) {
                    return true;
                }
            }
        } catch (Exception x) {
            x.printStackTrace();
        }
        return false;
    }

    String binPath = "/system/bin/su";
    String xBinPath = "/system/xbin/su";
    StringBuilder ret = new StringBuilder();
    /**
     * 判断Android设备是否拥有Root权限
     */
//    public boolean isRoot1() {
//
//        /*if (new File(binPath).exists() && isExecutable(binPath))
//            return true;
//        if (new File(xBinPath).exists() && isExecutable(xBinPath))
//            return true;*/
//        isExecutable();
//        return false;
//    }
    private boolean isExecutable() {
        Process p = null;
        try {
            Log.i("wei","into isExecutable 1111");
            p = Runtime.getRuntime().exec("ls -l system/xbin/su");
//            p=Runtime.getRuntime().exec(new String[]{"/system/bin/sh","c","su"});
            // 获取返回内容
            Log.i("wei","into isExecutable 2222");
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line ;
            ret.delete(0,ret.length());
            while ((line = in.readLine()) != null) {
                ret.append(line);
            }
            Log.i("wei","into isExecutable str : " + ret.toString());
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
        return false;
    }

    private static String exec(String[] exec) {
        if (exec == null || exec.length <= 0) {
            return null;
        }
        StringBuilder ret = new StringBuilder();
        ProcessBuilder processBuilder = new ProcessBuilder(exec);
        try {
            Process process = processBuilder.start();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                ret.append(line);
            }
            process.getInputStream().close();
            process.destroy();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret.toString();
    }


}
