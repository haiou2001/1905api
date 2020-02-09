<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Http\Request;
use GuzzleHttp\Client;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Redis;

use App\Model\UserModel;

class TestController extends Controller
{
    public function test()
    {

        echo '<pre>';print_r($_SERVER);echo '</pre>';
    }
public function sign()
    {
        //验签
        $data = "hello";
        $key = '1905';

        //计算签名
        $sign = md5($data . $key);

        echo '数据:'.$data;
        echo '<br>';
        echo '签名:'.$sign;

        //发送数据
        $url = 'http://1905user.com/user/sign?data='.$data.'&sign='.$sign;

        $res = file_get_contents($url);
        echo $res;
        echo '<hr>';
    }

    /**
     * 用户注册
     */
    public function reg(Request $request)
    {
        echo '<pre>';print_r($request->input());echo '</pre>';

        //验证用户名 验证email 验证手机号

        $pass1 = $request->input('pass1');
        $pass2 = $request->input('pass2');

        if($pass1 != $pass2){
            die("两次输入的密码不一致");
        }

        $password = password_hash($pass1,PASSWORD_BCRYPT);

        $data = [
            'email'         => $request->input('email'),
            'name'          => $request->input('name'),
            'password'      => $password,
            'mobile'        => $request->input('mobile'),
            'last_login'    => time(),
            'last_ip'       => $_SERVER['REMOTE_ADDR'],     //获取远程IP
        ];

        $uid = UserModel::insertGetId($data);
        var_dump($uid);
    }


    /**
     * 用户登录接口
     * @param Request $request
     * @return array
     */
    public function login(Request $request)
    {

        $name = $request->input('name');
        $pass = $request->input('pass');

        $u = UserModel::where(['name'=>$name])->first();
        if($u){
            //验证密码
            if( password_verify($pass,$u->password) ){
                // 登录成功
                //echo '登录成功';
                //生成token
                $token = Str::random(32);

                $response = [
                    'errno' => 0,
                    'msg'   => 'ok',
                    'data'  => [
                        'token' => $token
                    ]
                ];

            }else{
                $response = [
                    'errno' => 400003,
                    'msg'   => '密码不正确'
                ];
            }
        }else{
            $response = [
                'errno' => 400004,
                'msg'   => '用户不存在'
            ];
        }

        return $response;

    }

    /**
     * 获取用户列表
     * 2020年1月2日16:32:07
     */
    public function userList()
    {

        $list = UserModel::all();
        echo '<pre>';print_r($list->toArray());echo '</pre>';

    }


    public function postman()
    {
        echo __METHOD__;
    }


    public function login0()
    {
        //请求passport
        $url = 'http://passport.1905.com/api/user/login';
        $response = UserModel::curlPost($url,$_POST);
        return $response;
    }

        public function showData()
    {

        // 收到 token
        $uid = $_SERVER['HTTP_UID'];
        $token = $_SERVER['HTTP_TOKEN'];

        // 请求passport鉴权
        $url = 'http://passport.1905.com/api/auth';         //鉴权接口
        $response = UserModel::curlPost($url,['uid'=>$uid,'token'=>$token]);

        $status = json_decode($response,true);

        //处理鉴权结果
        if($status['errno']==0)     //鉴权通过
        {
            $data = "sdlfkjsldfkjsdlf";
            $response = [
                'errno' => 0,
                'msg'   => 'ok',
                'data'  => $data
            ];
        }else{          //鉴权失败
            $response = [
                'errno' => 40003,
                'msg'   => '授权失败'
            ];
        }

        return $response;

    }
    public function postman1()
    {
        echo '111';

    }

    public function add()
    {
        $key = "1905";          // 签名使用key  发送端与接收端 使用同一个key 计算签名

        //待签名的数据
        $order_info = [
            "order_id"          => 'LN_' . mt_rand(111111,999999),
            "order_amount"      => mt_rand(111,999),
            "uid"               => 12345,
            "add_time"          => time(),
        ];

        $data_json = json_encode($order_info);

        //计算签名
        $sign = md5($data_json.$key);

        // post 表单（form-data）发送数据
        $client = new Client();

        $url = 'http://1905user.com/user/check2';
        $response = $client->request("POST",$url,[
            "form_params"   => [
                "data"  => $data_json,
                "sign"  => $sign
            ]
        ]);

        //接收服务器端响应的数据
        $response_data = $response->getBody();
        echo $response_data;

    }

 public function key_sign()
    {
        $data = 'hello';

        //使用私钥加密
        $priv_key = storage_path('keys/priv1.key');
        $pkeyid = openssl_pkey_get_private("file://" . $priv_key);
        openssl_sign($data, $signature, $pkeyid);
        openssl_free_key($pkeyid);
        //base64编码签名
        //

        $sign = base64_encode($signature);
        echo '签名：' . $sign;
        echo '<br>';

        $url = "http://1905user.com/user/sign2?" . 'data=' . $data . '&sign=' . urlencode($sign);
        echo $url;
    }


    public function key_encrypt()
    {
        $data = "富二代";


        //使用非对称加密
        $priv_key = storage_path('keys/priv1.key');
        $pkeyid = openssl_pkey_get_private("file://" . $priv_key);

        openssl_private_encrypt($data,$encrypt,$pkeyid,OPENSSL_PKCS1_PADDING);

        $str = base64_encode($encrypt);

        echo '加密:'.$str;
        echo "<br>";
        //发送解密数据
        $url = "http://1905user.com/user/decrypt?data=" . urlencode($str);
        //$res = file_get_contents($url);
        $res=file_get_contents($url);
        //dd($res);die;
        echo $res;

    }
}
