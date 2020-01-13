package com.example.activitydemo;

import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

public class SignTools {

    //weiyw add for spit apk start
    private StringBuilder signTopInfo;//签名头信息
    private String hexStr =  "0123456789ABCDEF";
    private StringBuilder originalData = new StringBuilder();//原始apk长度
    private String publickeymodulus = "DCED130FF3840CBF0E6DF3CAA4D8DC7AFD59C2A1F64E7F932A16AB5E5705ABC26C6B41448BF1FCC114C03A1A2820AC4D47E56EB9A7BE3438E6DF190C34E4CC9F259A182ABAA2D52CF435E9EC53B3B02B00D7892E1E5DB5C10D57124731C536CFF9DCFB0B3EE4B29A9DCCDE0E1553E8C5324B89FE2D12F0E88E4ADAF57886CFBF8C4511CFDB6251939D7804D1F8051C2CCD1B62842F394692FC30D535424C2B1B9A6A12051162E1AE67012178002E74FB671EDCFDAE3981962A7D793E4E99C3BAB6575809E2739861BFF0DB2436ED50DBD2305C9ACB85320ACC1A3C7031219C30BB2F67476441F9AF9D15E77DD99D7254F2E513BF5022AF3D28C6B6E9E78822BD";
    private String publickeyExponent = "010001";
    private byte[] apkData = null;
    private byte[] apkDateReverse = null;
    private byte[] apkTopSignData = null;
    byte[] oriapk;

    /**
     * @author weiyw
     * @param originPath apk路径
     * @deprecated 此方法会读取apk初始化一些字段，需最先执行
     * @return 判断是否存在付临门签名头 ture:存在 false:不存在*,
     */
    public boolean hasFlmTopSign(String originPath) throws IOException {
        if(apkData != null || apkDateReverse != null || apkTopSignData != null){
            apkData = null;
            apkDateReverse = null;
            apkTopSignData = null;
        }
        apkData = readBigFileBytes(originPath);
        apkDateReverse = new byte[apkData.length];
        apkTopSignData = new byte[61];
        System.arraycopy(apkData,0,apkDateReverse,0,apkData.length);
        apkDateReverse = swapOrder(apkDateReverse);
        System.arraycopy(apkDateReverse,0,apkTopSignData,0,61);
        apkTopSignData = swapOrder(apkTopSignData);
        signTopInfo = byte2hex(apkTopSignData);
        CharSequence topSignName = signTopInfo.subSequence(0,4);
        if(topSignName.equals("130C")){
            Log.i("wei","此apk有签名头");
            return true;
        }
        return false;
    }

    /**
     * @author weiyw
     * @param originPath apk路径
     * @deprecated  提取付临门apk中的原始apk并替换
     */
    public void replaceFlmApkToOriginal(String originPath) {
        //读取出的十六进制原始apk长度
        int oriApklenth = getDatalenth(78,86);
        Log.i("wei","原始apk长度：" + oriApklenth);
        oriapk = new byte[oriApklenth];
        System.arraycopy(apkData,0,oriapk,0, oriApklenth);
        writeFile(oriapk,originPath);
    }

    /**
     * @author weiyw
     * @param originPath
     * @deprecated 有签名头的apk验签失败则还原apk
     */
    public void resetApk(String originPath){
        writeFile(apkData,originPath);
    }

    /**
     * @author weiyw
     * @param originPath apk路径
     * @deprecated 提取apk中附加的签名数据并对其解密并与对apk做SHA256摘要后的数据作对比
     * @return true:摘要相同 flase:摘要不相同
     */
    public Boolean testApkSign(String originPath) {
        //读取签名数据偏移量
        Boolean flag = false;
        int signDataOfset = getDatalenth(90, 98);
        Log.i("wei", "签名数据偏移量：" + signDataOfset);
        //读取签名数据长度
        int signDataLen = getDatalenth(102, 110);
        Log.i("wei", "签名数据长度:" + signDataLen);
        //读取签名数据
        byte[] signData = new byte[signDataLen];
        System.arraycopy(apkData, signDataOfset, signData, 0, signDataLen);
        replaceFlmApkToOriginal(originPath);
        PublicKey publicKey = null;
        try {
            publicKey = getPublicKey(publickeymodulus, publickeyExponent);
            byte[] signDataSHA1 = decryptByPublicKey(signData, publicKey.getEncoded());
            byte[] apkSHA1Data = getSHA1(new FileInputStream(originPath));
            flag = compereByteArray(signDataSHA1, apkSHA1Data);
            Log.i("wei","signDataSHA1:"+ Arrays.toString(signDataSHA1));
            Log.i("wei","apkSHA1Data: "+ Arrays.toString(apkSHA1Data));
            Log.i("wei", "flag:" + flag);
            return flag;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }finally {
            if(!flag){
                resetApk(originPath);
            }
        }
        return flag;
    }
    /**
     * @author weiyw
     * @param write_str
     * @return
     */
    public void writeFlagSDFile(String write_str) throws IOException {
        File file = new File("/sdcard/flm_sign.txt");
        FileOutputStream fos = new FileOutputStream(file);
        byte[] bytes = write_str.getBytes();
        fos.write(bytes);
        fos.close();
    }

    public  String readFlagSDFile() throws IOException {
        String flag = "0";
        File file = new File("/sdcard/flm_sign.txt");
        if(!file.exists()){
            return "0";
        }
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(file);
            if(inputStream != null) {
                InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                flag = bufferedReader.readLine();
                bufferedReader.close();
                inputStreamReader.close();
                inputStream.close();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }finally {

        }
        return flag;
    }

    private int getDatalenth(int start,int end) {
        originalData.setLength(0);
        CharSequence size_hex = signTopInfo.subSequence(start,end);
        //apkSize_hex反向2位读取得到原始apk的真正16位长度
        originalData.append(size_hex.subSequence(6,8));
        originalData.append(size_hex.subSequence(4,6));
        originalData.append(size_hex.subSequence(2,4));
        originalData.append(size_hex.subSequence(0,2));
        //将16进制转换成10进制
        return (int) Long.parseLong(String.valueOf(originalData),16);
    }

    //读取文件,小文件，如果超出缓存空间则会报错
    private byte[] readSmallFileBytes(String path) throws IOException {
        byte[] data = new byte[1024];
        File file = new File(path);
        FileInputStream fileInputStream = new FileInputStream(file);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        while (true){
            int i = fileInputStream.read(data);
            if(i != -1){
                byteArrayOutputStream.write(data,0,i);
            }else {
                return byteArrayOutputStream.toByteArray();
            }
        }
    }
    //可读取较大文件
    private byte[] readBigFileBytes(String path) {
        byte[] buffer = null;
        try {
            File file = new File(path);
            FileInputStream in = new FileInputStream(file);
            int fileLength = in.available();
            buffer = new byte[fileLength];
            in.read(buffer);
            in.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return buffer;
    }

    /**
     * 数组顺序颠倒
     */
    private byte[] swapOrder(byte[] arr){
        //只需一个循环，数组的一半就可以，第一个和最后一个交换，第二个和倒数第二个交换。。。
        int length = arr.length;
        for(int i=0;i<length/2;i++){
            byte temp = arr[i];
            arr[i] = arr[length-1-i];
            arr[length-1-i] = temp;
        }
        return arr;
    }

    /**
     * 将byte数组化为十六进制串
     */

    private final StringBuilder byte2hex(byte[] data) {
        StringBuilder stringBuilder = new StringBuilder(data.length);
        for (byte byteChar : data) {
            stringBuilder.append(String.format("%02X ", byteChar).trim());
        }
        return stringBuilder;
    }

    /**
     *
     * @param hexString
     * @return 将十六进制转换为二进制字节数组   16-2
     */
    private byte[] hexStr2BinArr(String hexString){
        //hexString的长度对2取整，作为bytes的长度
        int len = hexString.length()/2;
        byte[] bytes = new byte[len];
        byte high = 0;//字节高四位
        byte low = 0;//字节低四位
        for(int i=0;i<len;i++){
            //右移四位得到高位
            high = (byte)((hexStr.indexOf(hexString.charAt(2*i)))<<4);
            low = (byte)hexStr.indexOf(hexString.charAt(2*i+1));
            bytes[i] = (byte) (high|low);//高地位做或运算
        }
        return bytes;
    }

    /**
     * 将字节数组写入文件
     *
     * @param apkfile
     * @param path
     */
    private void writeFile(byte[] apkfile,String path) {
        try {

            File file = new File(path);
            FileOutputStream out = new FileOutputStream(file);
            out.write(apkfile);
            out.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private PublicKey loadPublicKey() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(new FileInputStream("sdcard/flm_public.cer"));
        PublicKey publicKey1 = cert.getPublicKey();
        return publicKey1;
    }

    private PublicKey getPublicKey(String modulus, String publicExponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger bigIntModulus = new BigInteger(modulus,16);
        BigInteger bigIntPrivateExponent = new BigInteger(publicExponent,16);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }
    /**
     * 公钥解密
     * @param data      待解密数据
     * @param publicKey 密钥
     * @return byte[] 解密数据
     */
    private byte[] decryptByPublicKey(byte[] data, byte[] publicKey) throws Exception {
        // 得到公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey keyPublic = kf.generatePublic(keySpec);
        // 数据解密
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, keyPublic);
        return cipher.doFinal(data);
    }

    /**
     * 获取文件SHA1摘要值
     * @param fileInputStream
     * @return
     */
    private byte[] getSHA1(InputStream fileInputStream){
        // 缓冲区大小
        int bufferSize = 256 * 1024;
        DigestInputStream digestInputStream = null;
        try{
            // 拿到一个SHA256转换器（这里可以换成MD5,SHA1）
            MessageDigest messageDigest =MessageDigest.getInstance("SHA256");
            // 使用DigestInputStream
            digestInputStream = new DigestInputStream(fileInputStream,messageDigest);
            // read的过程中进行SHA1处理，直到读完文件
            byte[] buffer =new byte[bufferSize];
            while (digestInputStream.read(buffer) > 0);
            // 获取最终的MessageDigest
            messageDigest= digestInputStream.getMessageDigest();
            // 拿到结果，也是字节数组，包含16个元素
            byte[] resultByteArray = messageDigest.digest();
            // 把字节数组转换成字符串
            return resultByteArray;
        }catch(Exception e) {
            return null;
        }finally{
            try{
                digestInputStream.close();
                fileInputStream.close();
            }catch (Exception e) {

            }
        }
    }

    private boolean compereByteArray(byte[] b1, byte[] b2) {
        if(b1.length == 0 || b2.length == 0 ){
            return false;
        }
        if (b1.length != b2.length) {
            return false;
        }
        boolean isEqual = true;
        for (int i = 0; i < b1.length && i < b2.length; i++) {
            if (b1[i] != b2[i]) {
                System.out.println("different");
                isEqual = false;
                break;
            }
        }
        return isEqual;
    }

    private byte[] decryptWithRSA(String encryedData, PublicKey publicKey) throws Exception {
        if (publicKey == null) {
            throw new NullPointerException("decrypt PublicKey is null !");
        }
        Cipher cipher = null;
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");// 此处如果写成"RSA"解析的数据前多出来些乱码
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] output = cipher.doFinal(Base64.decode(encryedData, Base64.URL_SAFE));
        //byte[] output = cipher.doFinal(encryedData.getBytes());
        return output;
    }
    //weiyw add for spit apk end
}
