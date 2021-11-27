package uk.co.crazyfools.antevpn;

import net.kyori.adventure.text.Component;
import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

import java.net.InetAddress;

public class PlayerListener implements Listener {

    @EventHandler
    public void onAsyncPlayerPreLoginEvent(AsyncPlayerPreLoginEvent event) {

        InetAddress playerIp = event.getAddress();

        Main.debugMessage("Login event detected: " + event.getName());

        if(!AnteVPN.onUUIDWhitelist(event.getUniqueId()) || !AnteVPN.onAddressWhitelist(event.getAddress())) {
            if (AnteVPN.isVPN(playerIp)) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, Component.text("VPN Detected!"));
            }
        } else {
            if(Main.debugMode == 1) {
                Main.logMessage(event.getName() + " is on the UUID whitelist.");
            }
        }
    }
}
