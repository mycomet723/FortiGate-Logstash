# ----------LISTEN FOR INCOMING MESSAGES----------
input {
    udp {
        port => 1514
        type => "syslog"
    }
 }

 # -----------FILTER FOR SYSLOG IP----------
    filter {
      if [type] == "syslog" {

        grok {
          match => [
            "message",
              '%{SYSLOG5424PRI}%{IP:SyslogIP}%{SPACE}%{GREEDYDATA:message}'
            ]
            overwrite => "message"
          }

# -----------FILTER FOR FIREWALL----------
      if ([SyslogIP] == "xxx.xxx.xxx.xxx") {
        grok {
          match => [
            "message",
              '%{TIMESTAMP_ISO8601}%{SPACE}%{BACULA_JOB}%{SPACE}%{IP:LogSourceIP}%{SPACE}%{NOTSPACE}%{SPACE}%{NOTSPACE}%{SPACE}%{NOTSPACE}%{SPACE}%{NOTSPACE}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Type}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:SubType}%{SPACE}%{GREEDYDATA:FWmessage}'
            ]
            overwrite => "FWmessage"
        }

#       -----Remove "" from SubType field-----
        mutate {
          gsub => [ "SubType", "\"", "" ]
        }

#         -----Filter for WEBFILTER traffic
          if ([SubType] == "webfilter") {
            grok {
              match => [ 
                 "FWmessage",
                   '%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{NOTSPACE}%{SPACE}%{NOTSPACE}%{SPACE}%{NOTSPACE}%{SPACE}%{WORD}=%{IP:SourceIP}%{SPACE}%{WORD}=%{NUMBER:SourcePort}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{WORD}=%{IP:DestinationIP}%{SPACE}%{WORD}=%{NUMBER:DestinationPort}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Service}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:URL}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Action}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:RequestType}%{SPACE}%{GREEDYDATA:FWmessage}'
              ]
              overwrite => "FWmessage"
            }
          }

#           -----Remove "" from RequestType field-----
            mutate {
              gsub => [ "RequestType", "\"", "" ]
            }

#           -----Filter for REFERRAL web traffic-----
            if ([RequestType] == "referral") {
              grok {
                match => [
                  "FWmessage",
                    '%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{NOTSPACE}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:URLCategory}'
                ]
              }
            }

#           -----Filter for DIRECT web traffic-----
            if ([RequestType] == "direct") {
              grok {
                match => [
                  "FWmessage",
                    '%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{WORD}=%{NUMBER}%{SPACE}%{WORD}=%{NUMBER}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{WORD}=%{NUMBER}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:URLCategory}'
                ]
              }
            }

#         -----Filter for APPLICATION traffic-----
          if ([SubType] == "app-ctrl") {
            grok {
              match => [
                "FWmessage",
                  '%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{NOTSPACE}%{SPACE}%{WORD}=%{NUMBER}%{SPACE}%{USER}=%{IP:SourceIP}%{SPACE}%{WORD}=%{IP:DestinationIP}%{SPACE}%{WORD}=%{NUMBER:SourcePort}%{SPACE}%{WORD}=%{NUMBER:DestinationPort}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Service}%{SPACE}%{NOTSPACE}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:ApplicationCategory}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Application}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Action}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:URL}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:ApplicationRisk}'
              ]
            }
          }

#         -----Filter for FORWARD traffic-----
          if ([SubType] == "forward") {
            grok {
              match => [
                "FWmessage",
                  '%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{NOTSPACE}%{SPACE}%{WORD}=%{IP:SourceIP}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{WORD}=%{NUMBER:SourcePort}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{WORD}=%{IP:DestinationIP}%{SPACE}%{WORD}=%{NUMBER:DestinationPort}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{NOTSPACE}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Action}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Service}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:DestinationCountry}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:SourceCountry}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{GREEDYDATA:FWmessage}'
              ]
              overwrite => "FWmessage"
             }
           }

#         -----Remove "" from Action field-----
          mutate {
            gsub => [ "Action", "\"", "" ]
          }

#         -----Filter for LOCAL traffic-----
          if ([SubType] == "local") {
            grok {
              match => [
                "FWmessage",
                  '%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{NOTSPACE}%{SPACE}%{WORD}=%{IP:SourceIP}%{GREEDYDATA:FWmessage}'
              ]
              overwrite => "FWmessage"
            }
          }

#         -----Filter for SYSTEM traffic-----
          if ([SubType] == "system") {
            grok {
              match => [
                "FWmessage",
                  '%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Description}%{SPACE}%{GREEDYDATA:FWmessage}'
              ]
              overwrite => "FWmessage"
            }
          }

#         -----Remove "" from Description field-----
          mutate {
            gsub => [ "Description", "\"", "" ]
          }

#           -----Filter for SYSTEM PERFORMANCE STATISTICS description-----
            if ([Description] == "System performance statistics") {
              grok {
                match => [
                  "FWmessage",
                    '%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{WORD}=%{NUMBER:CPU}%{SPACE}%{WORD}=%{NUMBER:Memory}%{SPACE}%{WORD}=%{NUMBER:Sessions}%{SPACE}%{WORD}=%{NUMBER:Disk}%{SPACE}%{WORD}=%{QUOTEDSTRING:Bandwidth}%{SPACE}'
                ]
              }
            }

#           -----Filter for ADMIN LOGIN SUCCESSFUL description-----
            if ([Description] == "Admin login successful") {
              grok {
                match => [
                  "FWmessage",
                    '%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:User}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Service}%{SPACE}%{WORD}=%{IP:SourceIP}%{SPACE}%{WORD}=%{IP}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Action}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Status}%{SPACE}%{GREEDYDATA:FWmessage}'
                ]
              }
            }

#           -----Filter for ADMIN LOGIN FAILED description-----
            if ([Description] == "Admin login failed") {
              grok {
                match => [
                  "FWmessage",
                    '%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:User}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Service}%{SPACE}%{WORD}=%{IP:SourceIP}%{SPACE}%{WORD}=%{IP}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Action}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Status}%{SPACE}%{GREEDYDATA:FWmessage}'
                ]
              }
            }

#           -----Filter for OBJECT CONFIGURED description-----
            if ([Description] == "Object configured") {
              grok {
                match => [
                  "FWmessage",
                    '%{EMAILLOCALPART}%{QUOTEDSTRING:User}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Action}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:ConfiguredPath}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:ConfiguredObject}%{GREEDYDATA:FWmessage}'
                ]
              }
            }

#           -----Filter for OBJECT ATTRIBUTE CONFIGURED description-----
            if ([Description] == "Object attribute configured") {
              grok {
                match => [
                  "FWmessage",
                    '%{EMAILLOCALPART}%{QUOTEDSTRING:User}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:Action}%{SPACE}%{NOTSPACE}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:ConfiguredPath}%{SPACE}%{EMAILLOCALPART}%{QUOTEDSTRING:ConfiguredObject}%{GREEDYDATA:FWmessage}'
                ]
              }
            }

#         -----Remove "" from all added fields-----
          mutate {
            add_field => { "LogSourceName" => "Firewall" }
            gsub => [ "Bandwidth", "\"", "" ]
            gsub => [ "DestinationCountry", "\"", "" ]
            gsub => [ "Application", "\"", "" ]
            gsub => [ "ApplicationCategory", "\"", "" ]
            gsub => [ "ApplicationRisk", "\"", "" ]
            gsub => [ "DestinationIP", "[dstip=]", "" ]
            gsub => [ "Service", "\"", ""]
            gsub => [ "SourceCountry", "\"", "" ]
            gsub => [ "Type", "\"", ""]
            gsub => [ "URL", "\"", ""]
            gsub => [ "URLCategory", "\"", "" ]
            gsub => [ "Action", "\"", "" ]
            gsub => [ "User", "\"", "" ]
            gsub => [ "Status", "\"", "" ]
            gsub => [ "ConfiguredObject", "\"", "" ]
            gsub => [ "ConfiguredPath", "\"", "" ]
          }
      }
      }
	}

# ----------OUTPUT DATA TO KIBANA----------
  output {
    if [type] == "oldlog" {
      elasticsearch {
        hosts => ["localhost:9200"]
        sniffing => false
        manage_template => false
        index => "<syslog-firewall-{now/d}>"
        document_type => "%{[@metadata][type]}"
      }
    }
    if [SyslogIP] == "xxx.xxx.xxx.xxx" {
      elasticsearch {
        hosts => ["localhost:9200"]
        sniffing => false
        manage_template => false
        index => "<syslog-firewall-{now/d}>"
        document_type => "%{[@metadata][type]}"
      }
    }
  }
