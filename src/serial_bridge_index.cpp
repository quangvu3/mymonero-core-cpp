//
//  serial_bridge_index.cpp
//  Copyright (c) 2014-2019, MyMonero.com
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are
//  permitted provided that the following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of
//	conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list
//	of conditions and the following disclaimer in the documentation and/or other
//	materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be
//	used to endorse or promote products derived from this software without specific
//	prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
//  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
//  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
//  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
//  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//
//
#include "serial_bridge_index.hpp"
//
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
//
#include "monero_fork_rules.hpp"
#include "monero_transfer_utils.hpp"
#include "monero_address_utils.hpp" // TODO: split this/these out into a different namespaces or file so this file can scale (leave file for shared utils)
#include "monero_paymentID_utils.hpp"
#include "monero_wallet_utils.hpp"
#include "monero_key_image_utils.hpp"
#include "wallet_errors.h"
#include "string_tools.h"
#include "ringct/rctSigs.h"
//
#include "serial_bridge_utils.hpp"

using namespace std;
using namespace boost;
using namespace cryptonote;
using namespace monero_transfer_utils;
using namespace monero_fork_rules;
//
using namespace serial_bridge;
using namespace serial_bridge_utils;
//
//
// Bridge Function Implementations
//
string serial_bridge::decode_address(const string address, const string nettype)
{
	auto retVals = monero::address_utils::decodedAddress(address, nettype_from_string(nettype));
	if (retVals.did_error) {
		return error_ret_json_from_message(*(retVals.err_string));
	}
	boost::property_tree::ptree root;
	root.put("isSubaddress", retVals.isSubaddress);
	root.put("publicViewKey", *(retVals.pub_viewKey_string));
	root.put("publicSpendKey", *(retVals.pub_spendKey_string));
	if (retVals.paymentID_string != none) {
		root.put("paymentId", *(retVals.paymentID_string));
	}
	//
	return ret_json_from_root(root);
}
bool serial_bridge::is_subaddress(const string address, const string nettype)
{
	return monero::address_utils::isSubAddress(address, nettype_from_string(nettype));
}
bool serial_bridge::is_integrated_address(const string address, const string nettype)
{
	return monero::address_utils::isIntegratedAddress(address, nettype_from_string(nettype));
}
string serial_bridge::new_integrated_address(const string address, const string paymentId, const string nettype)
{
	return monero::address_utils::new_integratedAddrFromStdAddr(address, paymentId, nettype_from_string(nettype));
}
string serial_bridge::new_payment_id()
{
	return monero_paymentID_utils::new_short_plain_paymentID_string();
}

string serial_bridge::newly_created_wallet(const string localeLanguageCode, const string nettype)
{
	monero_wallet_utils::WalletDescriptionRetVals retVals;
	bool r = monero_wallet_utils::convenience__new_wallet_with_language_code(
		localeLanguageCode,
		retVals,
		nettype_from_string(nettype)
	);
	bool did_error = retVals.did_error;
	if (!r) {
		return error_ret_json_from_message(*(retVals.err_string));
	}

	boost::property_tree::ptree root;
	root.put("mnemonic", std::string((*(retVals.optl__desc)).mnemonic_string.data(), (*(retVals.optl__desc)).mnemonic_string.size()));
	root.put("mnemonicLanguage", (*(retVals.optl__desc)).mnemonic_language);
	root.put("seed", (*(retVals.optl__desc)).sec_seed_string);
	root.put("address", (*(retVals.optl__desc)).address_string);
	root.put("publicViewKey", epee::string_tools::pod_to_hex((*(retVals.optl__desc)).pub_viewKey));
	root.put("privateViewKey", epee::string_tools::pod_to_hex((*(retVals.optl__desc)).sec_viewKey));
	root.put("publicSpendKey", epee::string_tools::pod_to_hex((*(retVals.optl__desc)).pub_spendKey));
	root.put("privateSpendKey", epee::string_tools::pod_to_hex((*(retVals.optl__desc)).sec_spendKey));
	//
	return ret_json_from_root(root);
}
bool serial_bridge::are_equal_mnemonics(const string mnemonicA, const string mnemonicB)
{
	return monero_wallet_utils::are_equal_mnemonics(mnemonicA, mnemonicB);
}
string serial_bridge::address_and_keys_from_seed(const string seed, const string nettype)
{
	monero_wallet_utils::ComponentsFromSeed_RetVals retVals;
	bool r = monero_wallet_utils::address_and_keys_from_seed(
		seed,
		nettype_from_string(nettype),
		retVals
	);
	bool did_error = retVals.did_error;
	if (!r) {
		return error_ret_json_from_message(*(retVals.err_string));
	}

	boost::property_tree::ptree root;
	root.put("address", (*(retVals.optl__val)).address_string);
	root.put("publicViewKey", epee::string_tools::pod_to_hex((*(retVals.optl__val)).pub_viewKey));
	root.put("privateViewKey", epee::string_tools::pod_to_hex((*(retVals.optl__val)).sec_viewKey));
	root.put("publicSpendKey", epee::string_tools::pod_to_hex((*(retVals.optl__val)).pub_spendKey));
	root.put("privateSpendKey", epee::string_tools::pod_to_hex((*(retVals.optl__val)).sec_spendKey));
	//
	return ret_json_from_root(root);
}
string serial_bridge::mnemonic_from_seed(const string seed, const string wordsetName)
{
	monero_wallet_utils::SeedDecodedMnemonic_RetVals retVals = monero_wallet_utils::mnemonic_string_from_seed_hex_string(
		seed,
		wordsetName
	);
	boost::property_tree::ptree root;
	if (retVals.err_string != none) {
		return error_ret_json_from_message(*(retVals.err_string));
	}
	root.put("retVal", std::string((*(retVals.mnemonic_string)).data(), (*(retVals.mnemonic_string)).size()));

	return ret_json_from_root(root);
}
string serial_bridge::seed_and_keys_from_mnemonic(const string mnemonic, const string nettype)
{
	monero_wallet_utils::WalletDescriptionRetVals retVals;
	bool r = monero_wallet_utils::wallet_with(
		mnemonic,
		retVals,
		nettype_from_string(nettype)
	);
	bool did_error = retVals.did_error;
	if (!r) {
		return error_ret_json_from_message(*retVals.err_string);
	}
	monero_wallet_utils::WalletDescription walletDescription = *(retVals.optl__desc);
	boost::property_tree::ptree root;
	root.put("seed", (*(retVals.optl__desc)).sec_seed_string);
	root.put("mnemonicLanguage", (*(retVals.optl__desc)).mnemonic_language);
	root.put("address", (*(retVals.optl__desc)).address_string);
	root.put("publicViewKey", epee::string_tools::pod_to_hex((*(retVals.optl__desc)).pub_viewKey));
	root.put("privateViewKey", epee::string_tools::pod_to_hex((*(retVals.optl__desc)).sec_viewKey));
	root.put("publicSpendKey", epee::string_tools::pod_to_hex((*(retVals.optl__desc)).pub_spendKey));
	root.put("privateSpendKey", epee::string_tools::pod_to_hex((*(retVals.optl__desc)).sec_spendKey));

	return ret_json_from_root(root);
}
string serial_bridge::validate_components_for_login(const string address, const string privateViewKey, const string privateSpendKey, const string seed, const string nettype)
{
	monero_wallet_utils::WalletComponentsValidationResults retVals;
	bool r = monero_wallet_utils::validate_wallet_components_with( // returns !did_error
		address,
		privateViewKey,
		privateSpendKey,
		seed,
		nettype_from_string(nettype),
		retVals
	);
	bool did_error = retVals.did_error;
	if (!r) {
		return error_ret_json_from_message(*retVals.err_string);
	}

	boost::property_tree::ptree root;
	root.put("isValid", retVals.isValid);
	root.put("isViewOnly", retVals.isInViewOnlyMode);
	root.put("publicViewKey", retVals.pub_viewKey_string);
	root.put("publicSpendKey", retVals.pub_spendKey_string);
	//
	return ret_json_from_root(root);
}

string serial_bridge::estimated_tx_network_fee(const string priority, const string feePerb, const string forkVersion)
{
	uint64_t fee = monero_fee_utils::estimated_tx_network_fee(
		stoull(feePerb),
		stoul(priority),
		monero_fork_rules::make_use_fork_rules_fn(stoul(forkVersion))
	);

	std::ostringstream o;
	o << fee;
	//
	boost::property_tree::ptree root;
	root.put("retVal", o.str());
	//
	return ret_json_from_root(root);
}

string serial_bridge::generate_key_image(const string txPublicKey, const string privateViewKey, const string publicSpendKey, const string privateSpendKey, const string outputIndex)
{
	crypto::secret_key sec_viewKey{};
	crypto::secret_key sec_spendKey{};
	crypto::public_key pub_spendKey{};
	crypto::public_key tx_pub_key{};
	{
		bool r = false;
		r = epee::string_tools::hex_to_pod(privateViewKey, sec_viewKey);
		if (!r) {
			return error_ret_json_from_message("Invalid private view key");
		}
		r = epee::string_tools::hex_to_pod(privateSpendKey, sec_spendKey);
		if (!r) {
			return error_ret_json_from_message("Invalid private spend key");
		}
		r = epee::string_tools::hex_to_pod(publicSpendKey, pub_spendKey);
		if (!r) {
			return error_ret_json_from_message("Invalid public spend key");
		}
		r = epee::string_tools::hex_to_pod(txPublicKey, tx_pub_key);
		if (!r) {
			return error_ret_json_from_message("Invalid tx public key");
		}
	}
	monero_key_image_utils::KeyImageRetVals retVals;
	bool r = monero_key_image_utils::new__key_image(
		pub_spendKey, sec_spendKey, sec_viewKey, tx_pub_key,
		stoull(outputIndex),
		retVals
	);
	if (!r) {
		return error_ret_json_from_message("Unable to generate key image"); // TODO: return error string? (unwrap optional)
	}
	boost::property_tree::ptree root;
	root.put("retVal", epee::string_tools::pod_to_hex(retVals.calculated_key_image));
	//
	return ret_json_from_root(root);
}
