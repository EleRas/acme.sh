#!/usr/bin/env sh

#
#RRPPROXY_User="username"
#
#RRPPROXY_Password="password"

RRPPROXY_Api="https://api.rrpproxy.net:8083/xmlrpc"

########  Public functions #####################

#Usage: add  _acme-challenge.www.domain.com   "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_rrpproxy_add() {
  fulldomain=$1
  txtvalue=$2

  RRPPROXY_User="${RRPPROXY_User:-$(_readaccountconf_mutable RRPPROXY_User)}"
  RRPPROXY_Password="${RRPPROXY_Password:-$(_readaccountconf_mutable RRPPROXY_Password)}"
  if [ -z "$RRPPROXY_User" ] || [ -z "$RRPPROXY_Password" ]; then
    RRPPROXY_User=""
    RRPPROXY_Password=""
    _err "You didn't specify RRPproxy user and password yet."
    return 1
  fi

  #save the api key and email to the account conf file.
  _saveaccountconf_mutable RRPPROXY_User "$RRPPROXY_User"
  _saveaccountconf_mutable RRPPROXY_Password "$RRPPROXY_Password"

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    _err "invalid domain"
    return 1
  fi
  _debug _sub_domain "$_sub_domain"
  _debug _domain "$_domain"

  _record="$_sub_domain 500 IN TXT $txtvalue"
  _info "Adding record '$_record'"
  _rrpproxy_add_record "$_domain" "$_record"

}

#fulldomain txtvalue
dns_rrpproxy_rm() {
  fulldomain=$1
  txtvalue=$2

  RRPPROXY_User="${RRPPROXY_User:-$(_readaccountconf_mutable RRPPROXY_User)}"
  RRPPROXY_Password="${RRPPROXY_Password:-$(_readaccountconf_mutable RRPPROXY_Password)}"
  if [ -z "$RRPPROXY_User" ] || [ -z "$RRPPROXY_Password" ]; then
    RRPPROXY_User=""
    RRPPROXY_Password=""
    _err "You didn't specify RRPproxy user and password yet."
    return 1
  fi

  #save the api key and email to the account conf file.
  _saveaccountconf_mutable RRPPROXY_User "$RRPPROXY_User"
  _saveaccountconf_mutable RRPPROXY_Password "$RRPPROXY_Password"

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    _err "invalid domain"
    return 1
  fi
  _debug _sub_domain "$_sub_domain"
  _debug _domain "$_domain"

  _debug "Getting txt records"

  xml_content=$(printf '<?xml version="1.0" encoding="UTF-8"?>
  <methodCall>
  <methodName>Api.xcall</methodName>
  <params>
   <param>
    <value>
     <struct>
      <member>
       <name>s_login</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>s_pw</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>command</name>
       <value>
        <string>QueryDNSZoneRRList</string>
       </value>
      </member>
      <member>
       <name>dnszone</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>type</name>
       <value>
        <string>TXT</string>
       </value>
      </member>
      <member>
       <name>name</name>
       <value>
        <string>%s</string>
       </value>
      </member>
     </struct>
    </value>
   </param>
  </params>
  </methodCall>' "$RRPPROXY_User" "$RRPPROXY_Password" "$_domain" "$_sub_domain")

  export _H1="Content-Type: text/xml"
  response="$(_post "$xml_content" "$RRPPROXY_Api" "" "POST")"

  if ! printf "%s" "$response" | grep "Command completed successfully" >/dev/null; then
    _err "Error could not get txt records"
    return 1
  fi

  if ! printf "%s" "$response" | grep "$_sub_domain" >/dev/null; then
    _info "Do not need to delete record"
  else
    _record=$(printf '%s' "$response" | _egrep_o "$_sub_domain[^<]+")
    _info "Deleting record '$_record'"
    _rrpproxy_delete_record "$_domain" "$_record"
  fi

}

####################  Private functions below ##################################

_get_root() {
  _debug "get root"

  domain=$1
  i=2
  p=1
  xml_content=$(printf '<?xml version="1.0" encoding="UTF-8"?>
  <methodCall>
  <methodName>Api.xcall</methodName>
  <params>
   <param>
    <value>
     <struct>
      <member>
       <name>s_login</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>s_pw</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>command</name>
       <value>
        <string>QueryDNSZoneList</string>
       </value>
      </member>
     </struct>
    </value>
   </param>
  </params>
  </methodCall>' "$RRPPROXY_User" "$RRPPROXY_Password")

  export _H1="Content-Type: text/xml"
  response="$(_post "$xml_content" "$RRPPROXY_Api" "" "POST")"

  if ! printf "%s" "$response" | grep "Command completed successfully" >/dev/null; then
    _err "Error could not get zones"
    return 1
  fi

  while true; do
    h=$(printf "%s" "$domain" | cut -d . -f $i-100)
    _debug h "$h"
    if [ -z "$h" ]; then
      #not valid
      return 1
    fi

    if _contains "$response" "$h"; then
      _sub_domain=$(printf "%s" "$domain" | cut -d . -f 1-$p)
      _domain="$h"
      return 0
    fi
    p=$i
    i=$(_math "$i" + 1)
  done
  return 1

}

_rrpproxy_delete_record() {
  domain=$1
  record=$2

  xml_content=$(printf '<?xml version="1.0" encoding="UTF-8"?>
  <methodCall>
  <methodName>Api.xcall</methodName>
  <params>
   <param>
    <value>
     <struct>
      <member>
       <name>s_login</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>s_pw</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>command</name>
       <value>
        <string>ModifyDNSZone</string>
       </value>
      </member>
      <member>
       <name>dnszone</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>DELRR0</name>
       <value>
        <string>%s</string>
       </value>
      </member>
     </struct>
    </value>
   </param>
  </params>
  </methodCall>' "$RRPPROXY_User" "$RRPPROXY_Password" "$domain" "$record")

  export _H1="Content-Type: text/xml"
  response="$(_post "$xml_content" "$RRPPROXY_Api" "" "POST")"

  if ! printf "%s" "$response" | grep "Command completed successfully" >/dev/null; then
    _err "Error"
    return 1
  fi
  return 0

}

_rrpproxy_add_record() {
  domain=$1
  record=$2

  xml_content=$(printf '<?xml version="1.0" encoding="UTF-8"?>
  <methodCall>
  <methodName>Api.xcall</methodName>
  <params>
   <param>
    <value>
     <struct>
      <member>
       <name>s_login</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>s_pw</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>command</name>
       <value>
        <string>ModifyDNSZone</string>
       </value>
      </member>
      <member>
       <name>dnszone</name>
       <value>
        <string>%s</string>
       </value>
      </member>
      <member>
       <name>ADDRR0</name>
       <value>
        <string>%s</string>
       </value>
      </member>
     </struct>
    </value>
   </param>
  </params>
  </methodCall>' "$RRPPROXY_User" "$RRPPROXY_Password" "$domain" "$record")

  export _H1="Content-Type: text/xml"
  response="$(_post "$xml_content" "$RRPPROXY_Api" "" "POST")"

  if ! printf "%s" "$response" | grep "Command completed successfully" >/dev/null; then
    _err "Error"
    return 1
  fi
  return 0
}
