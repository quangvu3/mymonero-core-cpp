//
//  serial_bridge_utils.hpp
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

#ifndef serial_bridge_utils_hpp
#define serial_bridge_utils_hpp
//
#include <string>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
//
#include "cryptonote_config.h"
//
namespace serial_bridge_utils
{
	using namespace std;
	using namespace boost;
	using namespace cryptonote;
	//
	// JSON convenience fns
	bool parsed_json_root(const string &args_string, boost::property_tree::ptree &json_root);
	//
	// JSON values
	network_type nettype_from_string(const string &nettype_string);
	string string_from_nettype(network_type nettype);
	//
	struct RetVals_Transforms
	{ // TODO: can these be generalized with generics?
		static string str_from(uint64_t v)
		{
			std::ostringstream o;
			o << v;
			return o.str();
		}
		static string str_from(uint32_t v)
		{
			std::ostringstream o;
			o << v;
			return o.str();
		}
		static string str_from(bool v)
		{
			std::ostringstream o;
			o << v;
			return o.str();
		}
	};
	optional<double> none_or_double_from(const boost::property_tree::ptree &json, const string &key);
	optional<bool> none_or_bool_from(const boost::property_tree::ptree &json, const string &key);
	//../
	string ret_json_from_root(const boost::property_tree::ptree &root);
	string error_ret_json_from_message(const string &err_msg);
	string error_ret_json_from_code(int code, optional<string> err_msg);
}

#endif /* serial_bridge_utils_hpp */
