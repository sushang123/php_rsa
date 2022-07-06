<?php

/**
 * RSA算法属于非对称加密算法,非对称加密算法需要两个秘钥:公开密钥(publickey)和私有秘钥(privatekey).公开密钥和私有秘钥是一对,如果公开密钥对数据进行加密,只有用对应的私有秘钥才能解密;如果私有秘钥对数据进行加密那么只有用对应的公开密钥才能解密.因为加密解密使用的是两个不同的秘钥,所以这种算法叫做非对称加密算法.简单的说就是公钥加密私钥解密,私钥加密公钥解密.
 * 需要给PHP打开OpenSSL模块
 * 生成公钥和私钥的链接:  http://web.chacuo.net/netrsakeypair
 * openssl_pkey_get_public //检查公钥是否可用
 * openssl_public_encrypt //公钥加密
 * openssl_pkey_get_private //检查私钥是否可用
 * openssl_private_decrypt //私钥解密
 *
 */

// $str = '封装测试';
$str = json_encode(['a' => 1, 'b' => 2, 'f' => 6,]);
$cdata = RSA_openssl($str);

var_dump($cdata);
echo "<hr>";
$ddata = RSA_openssl($cdata, 'decode');
var_dump($ddata);

/**
 * RSA数据加密解密
 * @param type $data
 * @param type $type encode加密  decode解密
 */
function RSA_openssl($data, $type = 'encode')
{
    if (empty($data)) {
        return 'data参数不能为空';
    }
    if (is_array($data)) {
        return 'data参数不能是数组形式';
    }

    $rsa_public = config('rsa_public');
    if (empty($rsa_public)) {
        $rsa_public = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmkANmC849IOntYQQdSgLvMMGm
8V/u838ATHaoZwvweoYyd+/7Wx+bx5bdktJb46YbqS1vz3VRdXsyJIWhpNcmtKhY
inwcl83aLtzJeKsznppqMyAIseaKIeAm6tT8uttNkr2zOymL/PbMpByTQeEFlyy1
poLBwrol0F4USc+owwIDAQAB
-----END PUBLIC KEY-----';
    }
    $rsa_private = config('rsa_private');
    if (empty($rsa_private)) {
        $rsa_private = '-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKaQA2YLzj0g6e1h
BB1KAu8wwabxX+7zfwBMdqhnC/B6hjJ37/tbH5vHlt2S0lvjphupLW/PdVF1ezIk
haGk1ya0qFiKfByXzdou3Ml4qzOemmozIAix5ooh4Cbq1Py6202SvbM7KYv89syk
HJNB4QWXLLWmgsHCuiXQXhRJz6jDAgMBAAECgYAIF5cSriAm+CJlVgFNKvtZg5Tk
93UhttLEwPJC3D7IQCuk6A7Qt2yhtOCvgyKVNEotrdp3RCz++CY0GXIkmE2bj7i0
fv5vT3kWvO9nImGhTBH6QlFDxc9+p3ukwsonnCshkSV9gmH5NB/yFoH1m8tck2Gm
BXDj+bBGUoKGWtQ7gQJBANR/jd5ZKf6unLsgpFUS/kNBgUa+EhVg2tfr9OMioWDv
MSqzG/sARQ2AbO00ytpkbAKxxKkObPYsn47MWsf5970CQQDIqRiGmCY5QDAaejW4
HbOcsSovoxTqu1scGc3Qd6GYvLHujKDoubZdXCVOYQUMEnCD5j7kdNxPbVzdzXll
9+p/AkEAu/34iXwCbgEWQWp4V5dNAD0kXGxs3SLpmNpztLn/YR1bNvZry5wKew5h
z1zEFX+AGsYgQJu1g/goVJGvwnj/VQJAOe6f9xPsTTEb8jkAU2S323BG1rQFsPNg
jY9hnWM8k2U/FbkiJ66eWPvmhWd7Vo3oUBxkYf7fMEtJuXu+JdNarwJAAwJK0YmO
LxP4U+gTrj7y/j/feArDqBukSngcDFnAKu1hsc68FJ/vT5iOC6S7YpRJkp8egj5o
pCcWaTO3GgC5Kg==
-----END PRIVATE KEY-----';
    }

    //私钥解密
    if ($type == 'decode') {
        $private_key = openssl_pkey_get_private($rsa_private);
        if (!$private_key) {
            return ('私钥不可用');
        }
        $return_de = openssl_private_decrypt(base64_decode($data), $decrypted, $private_key);
        if (!$return_de) {
            return ('解密失败,请检查RSA秘钥');
        }
        return $decrypted;
    }

    //公钥加密
    $key = openssl_pkey_get_public($rsa_public);
    if (!$key) {
        return ('公钥不可用');
    }
    //openssl_public_encrypt 第一个参数只能是string
    //openssl_public_encrypt 第二个参数是处理后的数据
    //openssl_public_encrypt 第三个参数是openssl_pkey_get_public返回的资源类型
    $return_en = openssl_public_encrypt($data, $crypted, $key);
    if (!$return_en) {
        return ('加密失败,请检查RSA秘钥');
    }
    return base64_encode($crypted);
}


function config($res)
{
    return '';
}
