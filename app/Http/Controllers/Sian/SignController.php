<?php

namespace App\Http\Controllers\Sign;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class SignController extends Controller
{


    public function sign1(){
        //代签名的数据
        $data='huangxiaobo123456';

        //密钥路劲
        $path=storage_path('keys/priv1.key');

        //获取钥
        $pkeyid=openssl_pkey_get_private("file://".$path);
        // dump($pkeyid);die;
        //非对称加密算法
        openssl_sign($data,$signature,$pkeyid,OPENSSL_ALGO_SHA256);
        // echo $signature;
        // 释放密钥资源
        openssl_free_key($pkeyid);

        //base64  编码   方便传输
        $sign_str=base64_encode($signature);
        $sign_url=urlencode($sign_str);

        $url='http://1905user.com/check?data='.$data.'&sign='.$sign_url;
        $get=file_get_contents($url);
        echo $get;

    }

    //对称加密
    public function aes(){
        echo '<hr>';
        $str=request()->input('str');
        // echo $str;
        $method='AES-256-CBC';  //加密方式
        $key='sbhsfubsfdfqwijpjpsjasfnkoihogub';    //加密的密钥
        $iv='jingtdjopvrfhutd';       //必须为16位
        $enc=base64_decode($str);
        $d=openssl_decrypt($enc,$method,$key,OPENSSL_RAW_DATA,$iv);
        echo '解密后的数据：'.$d;
    }

    //非对称加密
    public function rsa2(){
        $data='嘟嘟嘟嘟~~~~';
        $key=storage_path('keys/priv1.key');
        $keys=openssl_pkey_get_private('file://'.$key);
        //dump($keys);

        openssl_private_encrypt($data,$s,$keys);
        // echo $s;
        // echo '<hr>';
        $str=base64_encode($s);
        // echo $str;
        // echo '<hr>';
        $str_url=urlencode($str);
        // echo $str_url;
        $url='http://1905user.com/rsa2?str='.$str_url;
        $g=file_get_contents($url);
        echo $g;
    }
}
