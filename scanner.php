<?php
declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

class Scanner {
	/** @var array */
	private $config;

	public function __construct() {
		$this->config = require_once __DIR__ . '/config/config.php';
	}

	public function getSpaceMembers() : array {
		return $this->config['members'];
	}

	/**
	 * Performs a Nmap scan and returns all logged-in MAC addresses
	 *
	 * @return array
	 */
	private function doNmapScan() : array {
		return array_filter(explode("\n", shell_exec('sudo nmap -sP ' . $this->config['ipRange'] . ' | awk \'/MAC Address:/{print $3;}\' | sort')));
	}

	/**
	 * Mark the current state for all users
	 *
	 * @return array
	 */
	private function getUserState() : array {
		$membersInSpace = [];
		$nmapResults = $this->doNmapScan();
		foreach ($this->getSpaceMembers() as $id => $MACs) {
			$membersInSpace[$id] = false;
			foreach ($MACs as $MAC) {
				if (array_search($MAC, $nmapResults) !== false) {
					$membersInSpace[$id] = true;
					break;
				}
			}
		}
		return $membersInSpace;
	}

	/**
	 * Builds the URL to the endpoint
	 *
	 * @param string $url
	 * @return string
	 */
	private function buildUrl(string $url) : string {
		return 'https://'.$this->config['endpoint'].''.$url;
	}

	/**
	 * Get all already checked in users
	 *
	 * @return array
	 */
	private function getAlreadyCheckedInUsers() : array {
		$markedInSpace = [];
		$client = new GuzzleHttp\Client();
		$res = $client->request(
			'GET',
			$this->buildUrl('/api/check_ins'),
			[
				'headers' => [
					'Authorization' => 'Bearer ' . $this->config['accessToken'],
				],
			]
		);
		$currentlyCheckedIn = json_decode($res->getBody()->getContents(), true);
		foreach ($currentlyCheckedIn as $checkIn) {
			if(time() < strtotime($checkIn['valid_until'])) {
				$markedInSpace[$checkIn['membership_id']] = true;
			}
		}
		return $markedInSpace;
	}

	/**
	 * Check-in the member
	 *
	 * @param string $memberId
	 */
	private function checkInMember(string $memberId) {
		$client = new GuzzleHttp\Client();
		$client->post(
			$this->buildUrl('/api/memberships/' . $memberId . '/work_sessions'),
			[
				'headers' => [
					'Authorization' => 'Bearer ' . $this->config['accessToken'],
				],
				'proxy' => 'localhost:8888',
				'verify' => false,
			]
		);
	}

	/**
	 * Check-out the member
	 *
	 * @param string $memberId
	 */
	private function checkOutMember(string $memberId) {
		$client = new GuzzleHttp\Client();
		$client->delete(
			$this->buildUrl('https://smartspace.cobot.me/api/memberships/' . $memberId . '/check_ins/current'),
			[
				'headers' => [
					'Authorization' => 'Bearer ' . $this->config['accessToken'],
				],
				'proxy' => 'localhost:8888',
				'verify' => false,
			]
		);
	}

	public function scan() {
		$actualMemberStates = $this->getUserState();
		$onlineState = $this->getAlreadyCheckedInUsers();
		foreach($actualMemberStates as $memberId => $state) {
			// User is already marked as online
			if(isset($onlineState[$memberId])) {
				// If not found now checkout the user, do nothing otherwise
				if($state === false) {
					$this->checkOutMember($memberId);
				}
			} else {
				// User is not marked as online
				if($state === true) {
					$this->checkInMember($memberId);
				}
			}
		}
	}
}

$scanner = new Scanner();
$scanner->scan();
