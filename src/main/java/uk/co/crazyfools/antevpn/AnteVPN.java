package uk.co.crazyfools.antevpn;

import java.io.IOException;
import java.net.InetAddress;
import java.sql.*;

public class AnteVPN {

    public static boolean isVPN(InetAddress address) {
        // Cheapest: Check GOOD database
        if(Main.debugMode == 1) {
            Main.logMessage("Checking already permitted addresses...");
        }
       if(checkGoodCache(address)) {
           if(Main.debugMode == 1) {
               Main.logMessage("IP is present in good cache");
           }
           return false;
       }

        // Cheap: BOGON Check
        if(Main.debugMode == 1) {
            Main.logMessage("Running BOGON Check");
        }
        if(checkBogons(address)) {
            // Address is a BOGON
            return false;
        }
        // Cheap: Cache Check
        if(Main.debugMode == 1) {
            Main.logMessage("Running CACHE check");
        }
        if(checkBadCache(address)) {
            // Address is in BAD CACHE
            return true;
        }
        // Check Database
        if(Main.debugMode == 1) {
            Main.logMessage("Running BAD DATABASE check");
        }
        if(checkBadDatabase(address)) {
            // Address is in BAD DATABASE
            return true;
        }

        // Expensive: Address lookup
        if(Main.debugMode == 1) {
            Main.logMessage("Running VPN check");
        }

        if(lookupAddress(address)) {

            if(Main.debugMode == 1) {
                Main.logMessage("VPN Detected!");
            }
            // Address is a VPN
            return true;
        }
        return false;
    }

    private static boolean checkGoodCache(InetAddress address) {
        if(Main.cachedGoodAddresses.containsKey(address)) {
            // Check age on the address
            if(System.currentTimeMillis() > Main.cachedGoodAddresses.get(address) + 86400000) {
                // TODO: Periodic cleanup
                Main.cachedGoodAddresses.remove(address);
                return false;
            } else {
                return true;
            }
        }

        return false;
    }
    private static boolean checkBogons(InetAddress address) {
        if(address.getAddress()[0] == (byte) 0) {
            // 0.0.0.0/0
            if(Main.debugMode == 1) {
                Main.logMessage("Matched 0.0.0.0/0 Rule");
            }
            return true;
        } else if(address.getAddress()[0] == (byte) 10) {
            if(Main.debugMode == 1) {
                Main.logMessage("Matched 10.0.0.0/8 Rule");
            }
            // 10.0.0.0/8
            return true;
        } else if(address.getAddress()[0] == (byte) 127) {
            if(Main.debugMode == 1) {
                Main.logMessage("Matched 127.0.0.0/8 Rule");
            }
            // 127.0.0.0/8
            return true;
        } else if((address.getAddress()[0] == (byte) 192) && address.getAddress()[1] == (byte) 168) {
           // 192.168.0.0/16
            if(Main.debugMode == 1) {
                Main.logMessage("Matched 192.168.0.0/16 Rule");
            }
           return true;
        }
        // TODO: Add remainder https://ipgeolocation.io/resources/bogon.html
        // The address is not a BOGON
        return false;
    }

    private static boolean checkBadCache(InetAddress address) {
        if(Main.cachedBadAddresses.containsKey(address)) {
            // Cache Hit
            if(Main.debugMode == 1) {
                Main.logMessage("Address found in bad cache");
            }
            return true;
        }
            return false;
    }

    private static boolean checkBadDatabase(InetAddress address) {
        Connection connection = null;
        String sql = "SELECT address from ante_bad_address WHERE address=?";


        try {
            connection = DriverManager.getConnection(Main.anteDb);
        } catch (SQLException e) {
            e.printStackTrace();
        }

        try(PreparedStatement prepStatement = connection.prepareStatement(sql)) {
            prepStatement.setString(1, address.getHostAddress());
            ResultSet resultSet = prepStatement.executeQuery();
            Integer rows = 0;
            while(resultSet.next()) {
                rows++;
            }
            if(rows > 0) {
                return true;
            }

        } catch (SQLException e) {

            }







        return false;
    }


    private static void invalidResult(String provider) {
        // Unexpected Output, if recorded 3 or more times the provider is disabled
        if(Main.providerViolations.containsKey(provider)) {
            if(Main.providerViolations.get(provider) >= 3) {
                Main.providerDisabled.put(provider, System.currentTimeMillis());
                Main.logMessage(provider + " was disabled due to too many errors");
            }
            Main.providerViolations.replace(provider, Main.providerViolations.get(provider) + 1);
        } else {
            Main.providerViolations.put(provider, 1);
        }
    }

    private static void denyAccess(InetAddress address) {
        if(Main.totalAddressChecks.containsKey(address)) {
            Main.totalAddressChecks.remove(address);
        }
        if(!Main.cachedBadAddresses.containsKey(address)) {
            Main.cachedBadAddresses.put(address, System.currentTimeMillis());
        } else {
            Main.logMessage("Something went wrong with the bad address cache list.");
        }
    }

    private static boolean permitAccess(InetAddress address) {
        if(Main.totalAddressChecks.containsKey(address)) {
            if(Main.totalAddressChecks.get(address) >= 1) {
                Main.cachedGoodAddresses.put(address, System.currentTimeMillis());
                Main.totalAddressChecks.remove(address);
                return true;
            } else {
                Main.totalAddressChecks.replace(address, Main.totalAddressChecks.get(address) + 1);
            }
        } else {
            Main.totalAddressChecks.put(address, 1);
        }
        return false;
    }

    private static boolean lookupAddress(InetAddress address) {
        // Returns 0 for Good
        // Returns 1 for VPN
        // Returns 2 for Error
        // ---
        // Return 'true' for VPN
        // Return 'false' for no VPN

        Integer checkResult = 2;

        if(!Main.providerDisabled.containsKey("PROXYCHECK-IO")) {
            if(Main.debugMode == 1) {
                Main.logMessage("Trying proxycheck.io...");
            }

            checkResult = ExternalComms.proxyCheckIo(address);

            if(checkResult == 0) {
                if(permitAccess(address)) {
                    // PermitAcess will return false if more checks needed
                     return false;
                }
            } else if (checkResult == 1) {
                denyAccess(address);
                return true;
            } else {
                invalidResult("PROXYCHECK-IO");
            }

        }

        checkResult = 2;

        if(!Main.providerDisabled.containsKey("IPTROOPER")) {
            if(Main.debugMode == 1) {
                Main.logMessage("Trying IP Trooper...");
            }
            checkResult = ExternalComms.ipTrooper(address);

            if(checkResult == 0) {
                if(permitAccess(address)) {
                    // PermitAccess will return false if more checks needed
                    return false;
                }
            } else if(checkResult == 1) {
                denyAccess(address);
                return true;
            } else {
                invalidResult("IPTROOPER");
            }
        }

        checkResult = 2;

        if(!Main.providerDisabled.containsKey("IPQUALITYSCORE")) {
            if(Main.debugMode == 1) {
                Main.logMessage("Trying IP Quality Score...");
            }
            checkResult = ExternalComms.ipQualityScore(address);

            if(checkResult == 0) {
                if(permitAccess(address)) {
                    // PermitAccess will return false if more checks needed
                    return false;
                }
            } else if(checkResult == 1) {
                denyAccess(address);
                return true;
            } else {
                invalidResult("IPQUALITYSCORE");
            }
        }

        Main.logMessage("List of IP reputation providers has been exhausted...");
        // No VPN detected after using all providers
        return false;
    }
}
