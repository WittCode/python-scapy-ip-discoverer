import tkinter as tk
from tkinter import ttk
import scapy.all as scapy
import threading
import collections


def sniffing():
    # Function to get packets off the wire.
    # prn accepts a function that executes with each packet sniffed.
    # The sniff function passes the packet object as the one and only argument
    # into the function you specify in the prn argument.
    # stop_filter is the function applied to each packet to determine if we have to stop
    # the capture after this packet.
    # the function passed to stop sniffing will stop if it returns true.
    scapy.sniff(prn=find_ips, stop_filter=stop_sniffing)


def find_ips(packet):
    # Uncomment below to see the details of each packet.
    # print(packet.show())
    # Dictionary where key is local IP and value is IP address it is talking to.
    global src_ip_dict
    # The tkinter tree to hold all the values.
    global treev
    global subdomain

    print(packet.show())

    # Check if packet has IP layer.
    if 'IP' in packet:
        # Get the source IP.
        src_ip = packet['IP'].src
        # Get the destination IP.
        dst_ip = packet['IP'].dst
        # If source IP in subdomain continue.
        # Get the length of the subdomain.
        if src_ip[0:len(subdomain)] == subdomain:
            # If source IP is not registered, register it and add destination.
            if src_ip not in src_ip_dict:
                # Add to dictionary.
                # Why we are using a defaultdict because if the key doesn't exist it creates it.
                src_ip_dict[src_ip].append(dst_ip)
                # Insert the row into the tree and returns the item identifier of the newly created item.
                # The first argument is the parent which is blank because it is treev.
                # Text is what is displayed.
                # Index is an integer specifying where in the list of parent's children to insert the item.
                row = treev.insert('', index=tk.END, text=src_ip)
                # Insert into the row the destination ip as a child.
                treev.insert(row, tk.END, text=dst_ip)
                # Make it so the tree fills the whole width of container.
                treev.pack(fill=tk.X)
            # If source IP is registered check if destination is registered.
            else:
                # If destination IP isn't registered with source IP add it.
                if dst_ip not in src_ip_dict[src_ip]:
                    # Add the IP address to the dictionary, once more this is why we are
                    # using the defaultdict so if the key isn't there it creates it.
                    src_ip_dict[src_ip].append(dst_ip)
                    # Returns the current focus item which means the item that was last selected.
                    cur_item = treev.focus()
                    # The item() method queries or modifies the options for the specified item.
                    # The item() method gets a dictionary where we can get the attributes.
                    # We want the text attribute because it contains the source IP.
                    if treev.item(cur_item)['text'] == src_ip:
                        # If the IP address matches
                        treev.insert(cur_item, tk.END, text=dst_ip)


# If switch is true then the sniffing will stop.
def stop_sniffing(packet):
    global should_we_stop
    return should_we_stop


# Called when start button is clicked.
def start_button():
    print('Start button clicked.')
    global should_we_stop
    global thread
    global subdomain

    # Get the text from the entry bar.
    subdomain = subdomain_entry.get()

    # Has a thread been made yet or is it dead?
    if (thread is None) or (not thread.is_alive()):
        # If there is no thread or the thread is dead then continue or start sniffing for packets.
        should_we_stop = False
        # Create a separate thread so one can sniff for packets and the other
        # can run the mainloop() or GUI.
        # The thread will be executing the sniffing function.
        # Target is the callable object to be invoked by the run method.
        thread = threading.Thread(target=sniffing)
        # When a thread object is created its activity must be started by calling the
        # thread's start() method. This invokes the run() method in a separate thread of control.
        # Once started, threads run independently until the target function returns.
        thread.start()


# Called when stop button is clicked.
def stop_button():
    print('Stop button clicked')
    global should_we_stop
    # Set to true so no longer sniffs for packets.
    should_we_stop = True


# --- main ---

# sniff() is a long running function so the program can't return to mainloop()
# which gets key/mouse events from the system, sends events to widgets, redraws widgets,
# so it looks like it freezes so we have to use threading.
thread = None
# Variable that determines if we should stop sniffing for packets.
# When the program starts the button hasn't been clicked to sniff for packets yet so leave at true.
should_we_stop = True

subdomain = ''

# Usually a python dictionary throws a KeyError if you try to get an item that is not currently in the dictionary.
# Defaultdict will create any items that you try to access provided they do not exist yet.
# Here default items are created using a list which returns a new empty list object.
src_ip_dict = collections.defaultdict(list)

# The main container.
root = tk.Tk()
root.geometry('500x500')
root.title('Tomcat')

# Used to display items with hierarchy.
treev = ttk.Treeview(root, height=400)
# The column holding the tree can be accessed with the symbolic name #0.
# This column has the plus sign in it for expansion.
treev.column('#0')

# pack() organizes widgets in blocks before placing in the parent widget.
tk.Label(root, text='WittCode\'s Packet Sniffer', font="Helvetica 24 bold").pack()

tk.Label(root, text="Enter an IP Subdomain", font="Helvetica 16 bold").pack()

# Entry box to add text into
# ipady and ipadx are the internal padding that make the widget bigger
# pady is what sets the padding around the widget.
subdomain_entry = tk.Entry()
subdomain_entry.pack(ipady=5, ipadx=50, pady=10)

# Add a frame to house the buttons.
button_frame = tk.Frame(root)

# Create buttons where command is the function.
# Command - the function to be called when the button is clicked.
# Width - the width of the button in letters (if displaying text) or pixels (if displaying an image).
# Pack organizes the widgets in blocks before placing them in the parent widget.
# Side determines which side of the parent widget packs against: TOP (DEFAULT), BOTTOM, LEFT, OR RIGHT.
tk.Button(button_frame, text="Start sniffing", command=start_button, width=15, font='Helvetica 16 bold').pack(
    side=tk.LEFT)
tk.Button(button_frame, text="Stop sniffing", command=stop_button, width=15, font='Helvetica 16 bold').pack(
    side=tk.LEFT)

# Put the frame containing the buttons at the bottom.
button_frame.pack(side=tk.BOTTOM, pady=10)

# An infinite loop used to run the application, wait for an event to occur,
# and process the event as long as the window is not closed.
root.mainloop()
