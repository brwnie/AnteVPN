package uk.co.crazyfools.antevpn;

import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.*;
import java.util.*;

public class Main extends JavaPlugin {
    // PLUGIN NOT SAFE FOR HUMAN OR MACHINE CONSUMPTION
    // VPN Providers
    //
    // PROXYCHECK-IOP
    // IPTROOPER
    // IPQUALITYSCORE

    // This plugin
    static Plugin plugin;
    // Enable debug mode
    static Integer debugMode = 0;

    // Databases
    // URL of central database
    static String anteDb = "jdbc:sqlite:plugins/AnteVPN/anteDb.db";

    // Caching
    // Number of approvals an IP address has had
    static HashMap<InetAddress, Integer> totalAddressChecks = new HashMap<InetAddress, Integer>();
    // Addresses that have already been approved by the plugin
    static HashMap<InetAddress, Long> cachedGoodAddresses = new HashMap<InetAddress, Long>();
    // Addresses that have already been denied by the plugin
    static HashMap<InetAddress, Long> cachedBadAddresses = new HashMap<InetAddress, Long>();
    // TODO: Occasional Cleanup
    // Whitelisted UUIDs
    static HashMap<UUID, Long> cachedWhitelist = new HashMap<UUID, Long>();

    // Violation Flags
    // Number of failed lookups from a provider
    static HashMap<String, Integer> providerViolations = new HashMap<String, Integer>();

    // Toggles for VPN Checker Providers is disabled or not
    static HashMap<String, Long> providerDisabled = new HashMap<String, Long>();


    // API Keys for VPNs
    static HashMap<String, String> providerKeys = new HashMap<String, String>();

    // Log messages to console
    public static void logMessage(String s) {
        Bukkit.getConsoleSender().sendMessage(s);
    }

    private void registerListeners() {
        // Register Event Listeners

        if(Main.debugMode == 1) {
            logMessage("Registering Listeners");
        }
        Bukkit.getPluginManager().registerEvents(new PlayerListener(), this);
    }

    private void loadPluginOptions() {
        // Load plugin options and API keys

        File OptionsFile = new File("plugins/AnteVPN/options.yml");

        FileConfiguration pluginOptions = YamlConfiguration.loadConfiguration(OptionsFile);

        if(pluginOptions.isSet("API")) {
           String proxyCheckIo = pluginOptions.getString("API.PROXYCHECK-IO.Key");
           String ipQualityScore = pluginOptions.getString("API.IPQUALITYSCORE.Key");
           if(!proxyCheckIo.isEmpty()) {
               providerKeys.put("PROXYCHECK-IO", proxyCheckIo);
           }
           if(!ipQualityScore.isEmpty()) {
               providerKeys.put("ipQualityScore", ipQualityScore);
           }
        } else {
            pluginOptions.set("API.PROXYCHECK-IO.Enabled", "true");
            pluginOptions.set("API.PROXYCHECK-IO.Key", "");
            pluginOptions.set("API.PROXYCHECK-IO.Comment", "https://proxycheck.io/ - Optional Registration for API Key");

            pluginOptions.set("API.IPQUALITYSCORE.Enabled", "true");
            pluginOptions.set("API.IPQUALITYSCORE.Key", "");
            pluginOptions.set("API.IPQUALITYSCORE.Comment", "https://www.ipqualityscore.com/ - Requires Registration for API Key");

            pluginOptions.set("API.IPTROOPER.Enabled", "true");
            pluginOptions.set("API.IPTROOPER.Comment", "https://iptrooper.net/ - No API Key required for free tier");

            try {
                pluginOptions.save(OptionsFile);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void onEnable() {
        // Start plugin
        logMessage("AnteVPN is now starting up...");
        plugin = this;
        registerListeners();
        loadPluginOptions();
        createDatabase();
    }



    public void onDisable() {
        logMessage("AnteVPN is now shutting down...");
        saveBadToDatabase();
        saveWhitelistToDatabase();
    }

    private void createDatabase() {
        Connection connection = null;
        try {
            connection = DriverManager.getConnection(anteDb);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            logMessage("Could not connect to SQLite Database!");
        }

        String createTableBadAddresses = "CREATE TABLE IF NOT EXISTS ante_bad_address(id integer PRIMARY KEY, address text NOT NULL UNIQUE, timestamp NUMERIC NOT NULL);";
        String createTableGoodUuid = "CREATE TABLE IF NOT EXISTS ante_good_uuid(id integer PRIMARY KEY, uuid text NOT NULL UNIQUE";

        try(Statement statement = connection.createStatement()) {
            try {
                statement.execute(createTableBadAddresses);
            } catch (SQLException e) {
                logMessage("Error creating Bad Addresses Table");
                e.printStackTrace();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        try(Statement statement = connection.createStatement()) {
            try {
                statement.execute(createTableGoodUuid);
            } catch (SQLException e) {
                logMessage("Error creating Good Uuid Table");
                e.printStackTrace();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }



        try {
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private void saveWhitelistToDatabase() {
        Main.logMessage("Saving UUIDs to database");
        // Save bad addresses to database
        // TODO: Create and periodic save
        Main.logMessage("Saving bad addresses into database");

        Connection connection = null;

        try {
            connection = DriverManager.getConnection(anteDb);
        } catch (SQLException e) {
            logMessage("Could not connect to SQL Lite Database");
        }

        String sql = "INSERT IGNORE INTO ante_good_uuid(uuid, timestamp) SET(?,?)";
        for(Map.Entry<UUID, Long> entry : cachedWhitelist.entrySet()) {
            try(PreparedStatement prepStatement = connection.prepareStatement(sql)) {
                prepStatement.setString(1, entry.getKey().toString());
                prepStatement.setInt(2, entry.getValue().intValue());
                prepStatement.execute();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        try {
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private void saveBadToDatabase() {
        // Save bad addresses to database
        // TODO: Create and periodic save
        Main.logMessage("Saving bad addresses into database");

        Connection connection = null;

        try {
            connection = DriverManager.getConnection(anteDb);
        } catch (SQLException e) {
            logMessage("Could not connect to SQL Lite Database");
        }

        String sql = "INSERT IGNORE INTO ante_bad_address(address, timestamp) SET(?,?)";
        for(Map.Entry<InetAddress, Long> entry : cachedBadAddresses.entrySet()) {
            try(PreparedStatement prepStatement = connection.prepareStatement(sql)) {
                prepStatement.setString(1, entry.getKey().getHostAddress());
                prepStatement.setInt(2, entry.getValue().intValue());
                prepStatement.execute();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        try {
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }



    public UUID getUuid(String playerName) {
        // Returns the UUID of a Player
        if(Bukkit.getPlayer(playerName) != null) {
            Player player = Bukkit.getPlayer(playerName);
            return player.getUniqueId();
        } else if(Bukkit.getOfflinePlayerIfCached(playerName) != null) {
            OfflinePlayer player = Bukkit.getOfflinePlayerIfCached(playerName);
            return player.getUniqueId();
        }
        return null;
    }


    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {

        if(command.getName().equalsIgnoreCase("avpnwhitelist")) {
            if(args.length == 1) {
                if (sender instanceof Player) {
                    Player player = (Player)sender;
                    if(player.hasPermission("CFUK.AVPNWhitelist")) {
                       UUID targetUuid = getUuid(args[0]);
                       cachedWhitelist.put(targetUuid, System.currentTimeMillis());
                       return true;
                    }
                } else {
                        UUID targetUuid = getUuid(args[0]);
                        cachedWhitelist.put(targetUuid, System.currentTimeMillis());
                        return true;

                }
            }
            return false;
        }

        if(command.getName().equalsIgnoreCase("avpndebug")) {
            if(sender instanceof Player) {
                Player player = (Player)sender;
                if(player.hasPermission("CFUK.AVPNDebug")) {
                    debugModeToggle();
                    return true;
                }
            } else {
                debugModeToggle();
                return true;
            }
        }


        if(command.getName().equalsIgnoreCase("avpnsim")) {
            if(debugMode == 1) {
                if(args.length == 1) {
                    InetAddress address = null;
                    try {
                        address = InetAddress.getByName(args[0]);
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    }
                    logMessage("Trying IP address " + address + " against the VPN checker.");
                    AnteVPN.isVPN(address);
                    return true;
                } else if(args.length == 2) {
                    InetAddress address = null;
                    try {
                        address = InetAddress.getByName(args[0]);
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    }

                    if(args[1].equalsIgnoreCase("1")) {
                        logMessage("Trying IP address " + address + " against Proxycheck.io");
                            ExternalComms.proxyCheckIo(address);

                    } else if(args[1].equalsIgnoreCase("2")) {
                            logMessage("Trying IP address " + address + " against IPTrooper");
                            ExternalComms.ipTrooper(address);

                    } else if(args[1].equalsIgnoreCase("3")) {
                        logMessage("Trying IP address " + address + " against IP Quality Score");
                        ExternalComms.ipQualityScore(address);
                    }
                    return true;
                }
            }
            return true;
        }
        // No commands matched here
        return false;
    }

    private void debugModeToggle() {
        if(debugMode == 0) {
            debugMode = 1;
        } else {
            debugMode = 2;
        }
    }
}
