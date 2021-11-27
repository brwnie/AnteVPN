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
        // TODO: Allow bypass if player has permission
        InetAddress playerIp = event.getAddress();
        if(Main.debugMode == 1) {
            Main.logMessage("Login event detected: " + event.getName());
        }
        if(!AnteVPN.onWhitelist(event.getUniqueId())) {
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
