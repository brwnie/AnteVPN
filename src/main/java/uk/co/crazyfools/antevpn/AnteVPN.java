package uk.co.crazyfools.antevpn;

import java.io.IOException;
import java.net.InetAddress;
import java.sql.*;
import java.util.UUID;

public class AnteVPN {

    private static boolean onWhiteListUuidDatabase(UUID playerUuid) {

        Connection connection = null;
        String sql = "SELECT address from ante_good_uuid WHERE uuid=?";

        try {
            connection = DriverManager.getConnection(Main.anteDb);
        } catch (SQLException e) {
            e.printStackTrace();
        }

        try(PreparedStatement prepStatement = connection.prepareStatement(sql)) {
            prepStatement.setString(1, playerUuid.toString());
            ResultSet resultSet = prepStatement.executeQuery();
            Integer rows = 0;
            while(resultSet.next()) {
                rows++;
            }
            if(rows > 0) {
                return true;
            }

        } catch (SQLException e) {
            Main.logMessage("SQL error whilst checking whitelisted UUID database");
        }

        return false;
    }

    public static boolean onUUIDWhitelist(UUID playerUuid) {
        // Check online cache
        if(Main.cachedWhitelistUuid.contains(playerUuid)) {
            return true;
        }
        
        // Check database
        if(onWhiteListUuidDatabase(playerUuid)) {
            // Put the UUID into cache for quicker lookups in future
            Main.cachedWhitelistUuid.add(playerUuid);
            return true;
        }

        return false;
    }

    public static boolean isVPN(InetAddress address) {

        // Step 1: Check manually added UUID cache

        // Step 2: Check manually added IP cache

        // Step 3: Check automatic good IP addresses
        Main.debugMessage("Running known good addresses in cache.");

       if(checkGoodCache(address)) {
           return false;
       }

       // Step 4: Check BOGON IP addresses

        Main.debugMessage("Running BOGON Check");
        if(checkBogons(address)) {
            return false;
        }

        // Step 5: Check automatic bad IP addresses

        Main.debugMessage("Running CACHE check");

        if(checkBadCache(address)) {
            // Address is in BAD CACHE
            return true;
        }


        // Step 6: Check automatic bad IP database lookup

        Main.debugMessage("Running BAD DATABASE check");

        if(checkBadDatabase(address)) {
            return true;
        }

        // Step 7: Go to IP address reputation providers to run a check

        Main.debugMessage("Running VPN check");


        if(lookupAddress(address)) {
            // Address is a VPN
            return true;
        }

        return false;
    }

    private static boolean checkGoodCache(InetAddress address) {
        if(Main.cachedGoodAddresses.containsKey(address)) {
            // Check age on the address
            if(Main.cachedGoodAddresses.get(address) != 0L && System.currentTimeMillis() > Main.cachedGoodAddresses.get(address) + 86400000) {
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

            Main.debugMessage("Matched 0.0.0.0/0 Rule");

            return true;
        } else if(address.getAddress()[0] == (byte) 10) {

            Main.debugMessage("Matched 10.0.0.0/8 Rule");

            // 10.0.0.0/8
            return true;
        } else if(address.getAddress()[0] == (byte) 127) {

            Main.debugMessage("Matched 127.0.0.0/8 Rule");

            // 127.0.0.0/8
            return true;
        } else if((address.getAddress()[0] == (byte) 192) && address.getAddress()[1] == (byte) 168) {
           // 192.168.0.0/16

            Main.debugMessage("Matched 192.168.0.0/16 Rule");

           return true;
        }
        // TODO: Add remainder https://ipgeolocation.io/resources/bogon.html
        // The address is not a BOGON
        return false;
    }

    private static boolean checkBadCache(InetAddress address) {
        if(Main.cachedBadAddresses.containsKey(address)) {
            // Cache Hit

            Main.debugMessage("Address found in bad cache");

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
                Main.debugMessage("Address found in bad database");
                // TODO: Add to bad address cache
                return true;
            }

        } catch (SQLException e) {
                Main.logMessage("Error when looking up address in bad database");
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

        Integer checkResult = Main.numberChecks;

        if(!Main.providerDisabled.containsKey("PROXYCHECK-IO")) {

            Main.debugMessage("Trying proxycheck.io...");


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

            Main.debugMessage("Trying IP Trooper...");

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

            Main.debugMessage("Trying IP Quality Score...");

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

    public static boolean onAddressWhitelist(InetAddress address) {
        // Check online cache
        if(Main.cachedGoodAddresses.containsKey(address)) {
            // Update the time since the cache was used
            Main.cachedGoodAddresses.replace(address, System.currentTimeMillis());
            return true;
        }
        // Check database
        if(onWhiteListAddressDatabase(address)) {
            // Put the UUID into cache for quicker lookups in future
            Main.cachedGoodAddresses.put(address, System.currentTimeMillis());
            return true;
        }

        return false;
    }

    private static boolean onWhiteListAddressDatabase(InetAddress address) {

        Connection connection = null;
        String sql = "SELECT address from ante_good_ip WHERE address=?";

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
            Main.logMessage("SQL error whilst checking whitelisted address database");
        }

        return false;
    }
}
