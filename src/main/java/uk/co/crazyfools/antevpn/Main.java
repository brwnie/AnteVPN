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
    // PLUGIN IS NOT SAFE FOR HUMAN OR MACHINE CONSUMPTION
    // VPN Providers
    //
    // PROXYCHECK-IOP
    // IPTROOPER
    // IPQUALITYSCORE

    // This plugin
    static Plugin plugin;
    // Enable debug mode
    static Integer debugMode = 0;

    // Number of checks to pass validation
    static Integer numberChecks = 1;

    // Databases
    // URL of central database
    static String anteDb = "jdbc:sqlite:plugins/AnteVPN/anteDb.db";

    // Caching
    // Number of approvals an IP address has had
    static HashMap<InetAddress, Integer> totalAddressChecks = new HashMap<>();
    // Addresses that have already been approved by the plugin
    static HashMap<InetAddress, Long> cachedGoodAddresses = new HashMap<>();
    // Addresses that have already been denied by the plugin
    static HashMap<InetAddress, Long> cachedBadAddresses = new HashMap<>();
    // TODO: Occasional Cleanup

    // Whitelisted UUIDs
    // Use this for perm. whitelisted things
    static List<UUID> cachedWhitelistUuid = new ArrayList<>();
    static List<InetAddress> cachedWhitelistIp = new ArrayList<>();

    // Violation Flags
    // Number of failed lookups from a provider
    static HashMap<String, Integer> providerViolations = new HashMap<>();

    // Toggles for VPN Checker Providers is disabled or not
    static HashMap<String, Long> providerDisabled = new HashMap<>();


    // API Keys for VPNs
    static HashMap<String, String> providerKeys = new HashMap<>();

    // Log messages to console
    public static void logMessage(String s) {
        Bukkit.getConsoleSender().sendMessage("[AVPN] " + s);
    }

    // Log debug messages to console
    public static void debugMessage(String s) {
        if(debugMode == 1) {
            Bukkit.getConsoleSender().sendMessage("[AVPN-D] " + s);
        }
    }

    private void registerListeners() {
        // Register Event Listeners


        debugMessage("Registering Listeners");

        Bukkit.getPluginManager().registerEvents(new PlayerListener(), this);
    }

    private void loadPluginOptions() {
        // Load plugin options and API keys
        File OptionsFile = new File("plugins/AnteVPN/options.yml");

        FileConfiguration pluginOptions = YamlConfiguration.loadConfiguration(OptionsFile);

        if(pluginOptions.isSet("API")) {
           String proxyCheckIo = pluginOptions.getString("API.PROXYCHECK-IO.Key");
           Boolean proxyCheckIoEnabled = pluginOptions.getBoolean("API.PROXYCHECK-IO.Enabled");

           String ipQualityScore = pluginOptions.getString("API.IPQUALITYSCORE.Key");
           Boolean ipQualityScoreEnabled = pluginOptions.getBoolean("API.IPQUALITYSCORE.Enabled");

           numberChecks = pluginOptions.getInt("Options.Checks.Setting");

           if(!proxyCheckIo.isEmpty()) {
               logMessage("Disabling Proxycheck.io");
               providerKeys.put("PROXYCHECK-IO", proxyCheckIo);
           }

           if(!ipQualityScore.isEmpty() || !pluginOptions.getBoolean("IPQUALITYSCORE.Enabled")) {
               providerKeys.put("IPQUALITYSCORE", ipQualityScore);
           }

            if(!pluginOptions.getBoolean("API.PROXYCHECK-IO.Enabled")) {
                providerDisabled.put("PROXYCHECK-IO", System.currentTimeMillis());
            }

            if(!pluginOptions.getBoolean("API.IPTROOPER.Enabled")) {
               providerDisabled.put("IPTROOPER", System.currentTimeMillis());
            }

            if(!pluginOptions.getBoolean("API.IPQUALITYSCORE.Enabled")) {
                providerDisabled.put("IPQUALITYSCORE", System.currentTimeMillis());
            }

        } else {
            pluginOptions.set("API.PROXYCHECK-IO.Enabled", true);
            pluginOptions.set("API.PROXYCHECK-IO.Key", "");
            pluginOptions.set("API.PROXYCHECK-IO.Comment", "https://proxycheck.io/ - Optional Registration for API Key");

            pluginOptions.set("API.IPQUALITYSCORE.Enabled", true);
            pluginOptions.set("API.IPQUALITYSCORE.Key", "");
            pluginOptions.set("API.IPQUALITYSCORE.Comment", "https://www.ipqualityscore.com/ - Requires Registration for API Key");

            pluginOptions.set("API.IPTROOPER.Enabled", true);
            pluginOptions.set("API.IPTROOPER.Comment", "https://iptrooper.net/ - No API Key required for free tier");

            pluginOptions.set("Options.Checks.Setting", 1);
            pluginOptions.set("Options.Checks.Comment", "The number of VPN providers to check against");

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
        // Register player listeners
        registerListeners();
        // Load options into memory
        loadPluginOptions();
        // Create database tables if not already existing
        createDatabase();
        // Loading player whitelist and good IP addresses into memory
        loadGoodAddresses();
        loadGoodUuids();
    }

    private void loadGoodUuids() {
        // TODO: Complete this function
    }

    private void loadGoodAddresses() {
        // TODO: Complete this function
    }


    public void onDisable() {
        logMessage("AnteVPN is now shutting down...");
        // Save previously bad IPs to the database
        saveBadToDatabase();
        // Save player whitelist to the database
        saveUuidWhitelistToDatabase();
        // Save good IP addresses to the database
        saveIpWhitelistToDatabase();
        logMessage("AnteVPN shut down complete.");
    }

    private void saveIpWhitelistToDatabase() {
        Main.logMessage("Saving UUIDs to database");
        // Save good unlimited IP addresses to database
        Main.logMessage("Saving good IP addresses into database");

        Connection connection = null;

        try {
            connection = DriverManager.getConnection(anteDb);
        } catch (SQLException e) {
            logMessage("Could not connect to SQL Lite Database");
        }

        String sql = "INSERT IGNORE INTO ante_good_ip(address) SET(?)";
        for(Integer i = 0; i < cachedWhitelistIp.size(); i++) {
                try (PreparedStatement prepStatement = connection.prepareStatement(sql)) {
                    prepStatement.setString(1, cachedWhitelistIp.get(i).getHostAddress());
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

    private void createDatabase() {
        Connection connection = null;
        try {
            connection = DriverManager.getConnection(anteDb);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            logMessage("Could not connect to SQLite Database!");
        }

        // Bad IP addresses with expiry
        String createTableBadAddresses = "CREATE TABLE IF NOT EXISTS ante_bad_address(id integer PRIMARY KEY, address text NOT NULL UNIQUE, timestamp NUMERIC NOT NULL);";
        // Good UUIDs
        String createTableGoodUuid = "CREATE TABLE IF NOT EXISTS ante_good_uuid(id integer PRIMARY KEY, uuid text NOT NULL UNIQUE);";
        // Good IP addresses
        String createTableGoodAddress = "CREATE TABLE IF NOT EXISTS ante_good_ip(id integer PRIMARY KEY, address text NOT NULL UNIQUE);";

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

        try(Statement statement = connection.createStatement()) {
            try {
                statement.execute(createTableGoodAddress);
            } catch (SQLException e) {
                logMessage("Error creating Good IP Table");
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

    private void saveUuidWhitelistToDatabase() {
        Main.logMessage("Saving UUIDs to database");

        Connection connection = null;

        try {
            connection = DriverManager.getConnection(anteDb);
        } catch (SQLException e) {
            logMessage("Could not connect to SQL Lite Database");
        }

        String sql = "INSERT IGNORE INTO ante_good_uuid(uuid) SET(?)";
        for(Integer i = 0; i < cachedWhitelistUuid.size(); i++) {
            try(PreparedStatement prepStatement = connection.prepareStatement(sql)) {
                prepStatement.setString(1, cachedWhitelistUuid.get(i).toString());
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

    private void addCachedGoodAddress(InetAddress address) {
        cachedGoodAddresses.put(address, System.currentTimeMillis());
    }

    private InetAddress convertStringToInetAddress(String addressString) {
        InetAddress address;
        try {
            address = InetAddress.getByName(addressString);
            return address;
        } catch (UnknownHostException e) {
            return null;
        }
    }

    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {

        if(command.getName().equalsIgnoreCase("avpnstatus")) {
            // Shows the service status of the plugin
            if(sender instanceof Player) {
              Player player = (Player)sender;
              if(player.hasPermission("cfuk.avpnadmin")) {
                  displayServiceStatus(sender);
                  return true;
              }
            } else {
                displayServiceStatus(sender);
                return true;
            }
            return false;
        }

        if(command.getName().equalsIgnoreCase("avpnallowip")) {
            // Adds an IP address to permitted IPs
            if(args.length == 1) {
                if(sender instanceof Player) {
                    Player player = (Player)sender;
                    if(player.hasPermission("cfuk.avpnadmin")) {
                        InetAddress address = convertStringToInetAddress(args[0]);
                        if(address != null) {
                            cachedWhitelistIp.add(address);
                        } else {
                            sender.sendMessage("Invalid address");
                            return false;
                        }
                        return true;
                    }
                } else {
                    InetAddress address = convertStringToInetAddress(args[0]);
                    if(address != null) {
                        cachedWhitelistIp.add(address);
                    } else {
                        sender.sendMessage("Invalid address");
                        return false;
                    }
                    return true;
                }
            }
            return false;
        }

        if(command.getName().equalsIgnoreCase("avpnallowuser")) {
            // Adds a username to permitted UUIDs
            if(args.length == 1) {
                if (sender instanceof Player) {
                    Player player = (Player)sender;
                    if(player.hasPermission("cfuk.avpnadmin")) {
                       UUID targetUuid = getUuid(args[0]);
                       cachedWhitelistUuid.add(targetUuid);
                       return true;
                    }
                } else {
                        UUID targetUuid = getUuid(args[0]);
                        cachedWhitelistUuid.add(targetUuid);
                        return true;

                }
            }
            return false;
        }

        if(command.getName().equalsIgnoreCase("avpndebug")) {
            // Enables debug mode
            if(sender instanceof Player) {
                Player player = (Player)sender;
                if(player.hasPermission("cfuk.avpndebug")) {
                    debugModeToggle();
                    return true;
                }
            } else {
                debugModeToggle();
                return true;
            }
        }


        if(command.getName().equalsIgnoreCase("avpnsim")) {
            // Simulates an IP request to a server
            if(debugMode == 1) {
                if(args.length == 1) {
                    InetAddress address = null;
                    try {
                        address = InetAddress.getByName(args[0]);
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    }
                    logMessage("Trying IP address " + address + " against the VPN checker.");
                    AnteVPN.isVpn(address, UUID.randomUUID());
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


    private void displayServiceStatus(CommandSender sender) {
        sender.sendMessage("AnteVPN Alpha Builds");
        sender.sendMessage("---");
        sender.sendMessage("Number of IPs in good cache: " + cachedGoodAddresses.size());
        sender.sendMessage("Number of IPs in bad cache: " + cachedBadAddresses.size());
        sender.sendMessage("Number of usernames in saved whitelist: " + cachedWhitelistUuid.size());
        sender.sendMessage("Number of IPs in saved whitelist: " + cachedWhitelistIp.size());
        sender.sendMessage("Number of disabled providers:" + providerDisabled.size());
        sender.sendMessage("---");
    }

    private void debugModeToggle() {
        if(debugMode == 0) {
            debugMode = 1;
        } else {
            debugMode = 0;
        }
    }
}
