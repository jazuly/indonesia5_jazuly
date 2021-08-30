<?php

namespace App\Controllers;

use App\Models\UserModel;
use CodeIgniter\RESTful\ResourceController;
use Exception;
use \Firebase\JWT\JWT;

class User extends ResourceController
{
	public function register()
	{
			$userModel = new UserModel();

			$data = [
				"name" => $this->request->getVar("name"),
				"email" => $this->request->getVar("email"),
				"password" => password_hash($this->request->getVar("password"), PASSWORD_DEFAULT),
			];

			$userModel->insert($data);

			$response = [
				'status' => 200,
				"error" => false,
				'messages' => 'Successfully, user has been registered',
				'data' => []
			];

		return $this->respondCreated($response);
	}

	public function login()
	{
		$userModel = new UserModel();

		$userdata = $userModel->where("email", $this->request->getVar("email"))->first();

		if (!empty($userdata)) {

			if (password_verify($this->request->getVar("password"), $userdata['password'])) {
				$iat = time(); // current timestamp value
				$exp = $iat + getenv('JWT_TIME_TO_LIVE');

				$payload = array(
					"iss" => "The_claim",
					"aud" => "The_Aud",
					"iat" => $iat, // issued at
					"exp" => $exp, // expire time in seconds
					"data" => $userdata,
				);

				$token = JWT::encode($payload, getenv('JWT_SECRET_KEY'));

				$response = [
					'status' => 200,
					'error' => false,
					'messages' => 'User logged In successfully',
					'data' => [
						'token' => $token
					]
				];
				return $this->respondCreated($response);
			} else {

				$response = [
					'status' => 500,
					'error' => true,
					'messages' => 'Wrong Password / Email',
					'data' => []
				];
				return $this->respondCreated($response);
			}
		} else {
			$response = [
				'status' => 500,
				'error' => true,
				'messages' => 'User not found',
				'data' => []
			];
			return $this->respondCreated($response);
		}
	}

	public function profile()
    {
		try {
			$authHeader = $this->request->getHeader("Authorization");
		
			if (!$authHeader) {
				throw new Exception();
			}

			$authHeader = $authHeader->getValue();
			$token = $authHeader;

            $decoded = JWT::decode($token, getenv('JWT_SECRET_KEY'), array("HS256"));

            if ($decoded) {

                $response = [
                    'status' => 200,
                    'error' => false,
                    'messages' => 'User details',
                    'data' => [
                        'profile' => $decoded
                    ]
                ];
                return $this->respondCreated($response);
            }
        } catch (Exception $ex) {
          
            $response = [
                'status' => 401,
                'error' => true,
                'messages' => 'Access denied / Invalid token',
                'data' => []
            ];
            return $this->respondCreated($response);
        }
    }
}
