package uk.co.crazyfools.antevpn;

import net.kyori.adventure.text.Component;
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
        if(AnteVPN.isVPN(playerIp)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, Component.text("VPN Detected!"));
        }
    }
}
