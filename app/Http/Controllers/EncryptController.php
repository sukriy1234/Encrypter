<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Validator;

class EncryptController extends Controller
{
    public function validator_request(Request $request)
    {
        $validator = Validator::make($request->all(), [
           'file' => 'max:10240|required|mimes:csv,txt',
           'code' => 'required'
       ]);
        if ($validator->fails()) {
            $array = array(
                'error' => 'true',
                'message' => $validator->messages()->first(),
              );
            return $array;
        }
        if (strlen(base64_decode($request->code)) != 32) {
            $array = array(
              'error' => 'true',
              'message' => 'Code not valid'
            );
            return $array;
        }

        $file = $request->file('file');
        return $this->encrypt($file, $request->code);
    }
    private function encrypt($file, $key)
    {
        $dkey = base64_decode($key);
        $encrypter = new Encrypter($dkey, 'AES-256-CBC');
        $fileDir = pathinfo($file->getRealPath());

        $handle = fopen($file, 'r');
        $txt = '';
        if ($handle) {
            while (!feof($handle)) {
                $plaintext = fgetss($handle);
                $ciphertext = $encrypter->encrypt($plaintext);
                if (feof($handle)) {
                    $txt .= $ciphertext;
                } else {
                    $txt .= $ciphertext."\r\n";
                }
            }
            fclose($handle);
            $array = array(
              'error' => pathinfo($file->getClientOriginalName(), PATHINFO_FILENAME).'.enc',
              'message' => $txt
            );
            return $array;
        }
    }
}
