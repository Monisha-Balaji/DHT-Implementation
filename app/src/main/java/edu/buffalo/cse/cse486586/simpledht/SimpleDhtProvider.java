package edu.buffalo.cse.cse486586.simpledht;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;

public class SimpleDhtProvider extends ContentProvider {


    private static final String TAG = SimpleDhtProvider.class.getName();
    static final int SERVER_PORT = 10000;
    private static final String KEY_FIELD = "key";
    private static final String VALUE_FIELD = "value";
    String[] PORTS= new String[]{"11108","11112","11116","11120","11124"};
    ArrayList<String> portlist = new ArrayList<String>();
    HashMap<String,String> fileMap = new HashMap<String,String>();
    HashMap<String,String> fileMap1 = new HashMap<String,String>();
    public Uri uri=null;
    String myPort="";
    String pred="";
    String succ="";
    String succ_unhash="";
    String pred_unhash = "";
    String[] ports = new String[50];
    String[] unhashed = new String[50];
    ArrayList<String> querydata = new ArrayList<String>();


    @Override
    // Reference: https://stackoverflow.com/questions/23892257/contentprovider-openfile-how-to-delete-file
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        try{
        Integer avd = Integer.parseInt(myPort);
        avd = avd / 2;
        String myporthash = genHash(avd.toString());
        if(selection.equals("@")){
            boolean flag;
            String[] filelist = getContext().fileList();
            File directory = getContext().getFilesDir();
            for(int i=0;i<filelist.length;i++){
                File file = new File(directory,filelist[i]);
                if (file.exists()) {
                    flag = file.delete();
                    if(flag==true) {
                        Log.i(TAG, "File" + i + "deleted");
                    }
                }
            }

        }
        else if(selection.equals("*")) {
            if (succ.equals("") && pred.equals("")) {
                boolean flag;
                String[] filelist = getContext().fileList();
                File directory = getContext().getFilesDir();
                for (int i = 0; i < filelist.length; i++) {
                    File file = new File(directory, filelist[i]);
                    if (file.exists()) {
                        flag = file.delete();
                        if (flag == true) {
                            Log.i(TAG, "File" + i + "deleted");
                        }
                    }
                }
            } else {
                boolean flag;
                String[] filelist = getContext().fileList();
                File directory = getContext().getFilesDir();
                for (int i = 0; i < filelist.length; i++) {
                    File file = new File(directory, filelist[i]);
                    if (file.exists()) {
                        flag = file.delete();
                        if (flag == true) {
                            Log.i(TAG, "File" + i + "deleted");
                        }
                    }
                }
                String msg = "Important:delete all";
                for (int i = 0; i < ports.length; i++) {
                    String temp = fileMap1.get(ports[i]);
                    if (!myporthash.equals(ports[i])) {
                        Integer port = Integer.parseInt(temp) * 2;
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                port);
                        PrintWriter out = new PrintWriter(socket.getOutputStream(), true); // Output Stream that client uses to send messages
                        Log.i(TAG, "Message to send in the for : " + msg);
                        out.println(msg); //Sends the message
                        Log.i(TAG, "Message sent " + msg);
                        out.flush();
                        socket.close();

                    }
                }
            }
        }
            else {
            String keyhash = genHash(selection);
            if (succ.equals("") && pred.equals("")) {
                boolean flag;
                File directory = getContext().getFilesDir();
                    File file = new File(directory,selection);
                    if (file.exists()) {
                        flag = file.delete();
                        if(flag==true) {
                            Log.i(TAG, "File" + "deleted");
                        }
                    }
            } else if ((pred.compareTo(myporthash) > 0) && ((keyhash.compareTo(myporthash) <= 0) || (keyhash.compareTo(pred) > 0))) {
                boolean flag;
                File directory = getContext().getFilesDir();
                File file = new File(directory,selection);
                if (file.exists()) {
                    flag = file.delete();
                    if(flag==true) {
                        Log.i(TAG, "File" + "deleted");
                    }
                }
            } else if (!(pred.compareTo(myporthash) > 0) && ((keyhash.compareTo(myporthash) <= 0) && (keyhash.compareTo(pred) > 0))) {
                boolean flag;
                File directory = getContext().getFilesDir();
                File file = new File(directory,selection);
                if (file.exists()) {
                    flag = file.delete();
                    if(flag==true) {
                        Log.i(TAG, "File" + "deleted");
                    }
                }
            }
            else{
                int size = ports.length;
                String diff = selection + ":" + "key delete";
                Integer portTosend =0;

                for(int i=0;i<ports.length;i++){
                    if((i!=(size-1) && ((keyhash.compareTo(ports[i])>0) && (keyhash.compareTo(ports[i+1])<=0)))){
                        String temp = fileMap1.get(ports[i+1]);
                        portTosend = Integer.parseInt(temp)*2;
                    }
                    else if((keyhash.compareTo(ports[size-1])>0) || (keyhash.compareTo(ports[0])<=0)){
                        String temp =fileMap1.get(ports[0]);
                        portTosend = Integer.parseInt(temp)*2;
                    }
                }
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        portTosend);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true); // Output Stream that client uses to send messages
                Log.i(TAG, "Message to send : " + diff);
                out.println(diff); //Sends the message
                Log.i(TAG, "Message sent " + diff);
                out.flush();
                socket.close();

            }

        }

        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub
        // Files are used to store the <key,value> pairs

        String filename = values.get(KEY_FIELD).toString();
        String value = values.get(VALUE_FIELD).toString();
        Log.i("Query", "ports - " + Arrays.toString(ports));
        Log.i(TAG, "key received in insert methond: " + filename);
        Log.i(TAG, "value received in insert methond : " + value);
        Log.i(TAG, "Pred for " + myPort + " : " + pred);
        Log.i(TAG, "Succ for " + myPort + " : "  + succ);



        Integer avd = Integer.parseInt(myPort);
        avd = avd / 2;
        int size = ports.length;
        FileOutputStream outputStream;
        try {

            String myporthash = genHash(avd.toString());
            String headnode = ports[0];
            String keyhash = genHash(filename);
            // Checking if there is only a single node in the list

            if(succ.equals("") && pred.equals("")){
                outputStream = getContext().openFileOutput(filename, Context.MODE_PRIVATE);
                outputStream.write(value.getBytes());
                outputStream.flush();
                outputStream.close();
                Log.d("Query", "Inserted in my avd - " + filename + " - " + value);
                //Log.i("Inserted SinNode  ", "filename : " + filename + " value :" + values.get(VALUE_FIELD).toString());
            Log.i(TAG,"Key inserted");
            }
            // Checking if the current node is the first node in the list i.e header node
            if(pred.compareTo(myporthash)>0){
                // Checking if key lies behind the current node or after the pred
                if((keyhash.compareTo(myporthash)<=0) || (keyhash.compareTo(pred)>0) ){
                    outputStream = getContext().openFileOutput(filename, Context.MODE_PRIVATE);
                    outputStream.write(value.getBytes());
                    outputStream.close();
                    Log.d("Query", "Inserted in my avd - " + filename + " - " + value);
                    //Log.i("Inserted pred>succ(if)", "filename : " + filename + " value :" + values.get(VALUE_FIELD).toString());
                    Log.i(TAG,"Key inserted");
                }
                else{
                    // Now forward to the successor node
                    Log.i("pred>succ(el)", "filename : " + filename + " value :" + values.get(VALUE_FIELD).toString());
                    String contentvalue = filename + ";" + value;
                    String msg = "insert";
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, myPort, msg, contentvalue);
                }
            }
            else{
                if((keyhash.compareTo(myporthash)<=0) && (keyhash.compareTo(pred)>0) ){
                    outputStream = getContext().openFileOutput(filename, Context.MODE_PRIVATE);
                    outputStream.write(value.getBytes());
                    outputStream.close();
                    Log.d("Query", "Inserted in my avd - " + filename + " - " + value);
                    //Log.i("ELSE pred>succ(IF)", "filename : " + filename + " value :" + values.get(VALUE_FIELD).toString());
                    Log.i(TAG,"Key inserted");
                }
                else{
                    //Log.i("ELSE pred>succ(eli)", "filename : " + filename + " value :" + values.get(VALUE_FIELD).toString());
                    String contentvalue = filename + ";" + value;
                    String msg = "insert";
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, myPort, msg, contentvalue);
                }
            }
        }
        catch (Exception e) {
        Log.e(TAG, "File write failed : " + e.getMessage());
        }
        Log.v("insert", values.toString());
        return uri;
        }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub

        String msg="";
        Log.i(TAG, "Inside Oncreate");
        TelephonyManager tel = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        uri = buildUri("content", "edu.buffalo.cse.cse486586.simpledht.provider");

        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            Log.e(TAG, "Can't create a ServerSocket");
            return false;
        }

        msg = " new join";
        if(myPort.equals("11108")){
            Log.d(TAG, "MyPort Value: "+myPort);
            try {
                Log.i(TAG, "Port no 11108");
                portlist.add(genHash(portStr));
                Log.i(TAG, "Hashed and added inside 11108");
                fileMap.put(genHash(portStr),portStr);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        else {
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, portStr, msg);
            Log.i(TAG, "Initiate client task to port "+ myPort);
        }
        return false;
    }

    //http://developer.android.com/reference/android/database/MatrixCursor.html
    // Reference:
    // 1. https://www.androidinterview.com/android-internal-storage-read-and-write-text-file-example/
    // 2. https://docs.oracle.com/javase/8/docs/api/?java/io/FileInputStream.html
    // Reads string from the file and stores the data as rows into the Matrixcursor
    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {
        // TODO Auto-generated method stub
        ArrayList<String> matrixdata = new ArrayList<String>();
        Integer avdno = Integer.parseInt(myPort)/2;

        if(selection.equals("@")) {
            String[] filelist = getContext().fileList();
            //File directory = getContext().getFilesDir();t
            MatrixCursor matrixCursor = new MatrixCursor( new String[]{"key", "value"});
            try {
                for(int i=0;i<filelist.length;i++) {
                    //File file = new File(directory, filelist[i]);
                    FileInputStream filestream = getContext().openFileInput(filelist[i]);
                    BufferedReader buf = new BufferedReader(new InputStreamReader(filestream));
                    String value = buf.readLine();
                    if(value!=null) {
                        String[] rowdata = new String[]{filelist[i], value};
                        Log.i(TAG, "query key we got : " + filelist[i]);
                        Log.i(TAG, "query- value we got : " + value);
                        matrixCursor.addRow(rowdata);
                        buf.close();
                        Log.i(TAG, "Query @: ");
                    }
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

            Log.v("query", selection);
            return matrixCursor;
        }

        else if(selection.equals("*")) {
            if( (succ.equals("") && pred.equals(""))){
                String msg = "query all";
                String sendmdata;
                String[] filelist = getContext().fileList();
                //File directory = getContext().getFilesDir();
                MatrixCursor matrixCursor = new MatrixCursor(new String[]{"key", "value"});
                try {
                    for (int i = 0; i < filelist.length; i++) {
                        //File file = new File(directory, filelist[i]);
                        FileInputStream filestream = getContext().openFileInput(filelist[i]);
                        BufferedReader buf = new BufferedReader(new InputStreamReader(filestream));
                        String value = buf.readLine();
                        if (value != null) {
                            String[] rowdata = new String[]{filelist[i], value};
                            Log.i(TAG, "query key we got : " + filelist[i]);
                            Log.i(TAG, "query- value we got : " + value);
                            matrixCursor.addRow(rowdata);
                            String temp = filelist[i] + "=" + value;
                            matrixdata.add(temp);
                            buf.close();
                        }
                    }
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                Log.v("query", selection);
                return matrixCursor;
                //return  null;
            }
            else{
                Log.i("Query","Inside query *");
                String sendmdata="";
                String total="";
                String[] filelist = getContext().fileList();
                Integer size = filelist.length;
                Log.i("Query","Inside query * printing flist length" + size.toString());
                //File directory = getContext().getFilesDir();
                MatrixCursor matrixCursor = new MatrixCursor(new String[]{"key", "value"});
                try {
                    String myporthash = genHash(avdno.toString());
                    for (int i = 0; i < filelist.length; i++) {
                        //File file = new File(directory, filelist[i]);
                        FileInputStream filestream = getContext().openFileInput(filelist[i]);
                        BufferedReader buf = new BufferedReader(new InputStreamReader(filestream));
                        String value = buf.readLine();
                        if (value != null) {
                            //String[] rowdata = new String[]{filelist[i], value};
                            Log.i(TAG, "query key we got : " + filelist[i]);
                            Log.i(TAG, "query- value we got : " + value);
                            //matrixCursor.addRow(rowdata);
                            String temp = filelist[i] + "=" + value;
                            matrixdata.add(temp);
                            buf.close();
                        }
                    }
                    //sendmdata = matrixdata.get(0);
                for(int i=0;i<matrixdata.size();i++){
                    sendmdata = sendmdata + matrixdata.get(i) + "," ;
                }
                    Log.i(TAG, "Appended list : " + sendmdata);
                    Log.i(TAG, "Alive nodes list: " + ports.length);
                    for(int i=0;i<ports.length;i++){
                        String temp = fileMap1.get(ports[i]);
                        if(!myporthash.equals(ports[i])){
                            String msg = "Important:query all";
                            Integer port = Integer.parseInt(temp)*2;
                            Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    port);
                            PrintWriter out = new PrintWriter(socket.getOutputStream(), true); // Output Stream that client uses to send messages
                            Log.i(TAG, "Message to send in the for : " + msg);
                            out.println(msg); //Sends the message
                            Log.i(TAG, "Message sent " + msg);

                            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                            String ack = in.readLine();
                            total = total + ack;
                            Log.i("Query", "list from other avds" + total);
                            in.close();
                            out.flush();
                            socket.close();

                        }
                    }
                    sendmdata = sendmdata + total;
                    Log.i("Query", "FInal data " + sendmdata);
                    String[] pairs = sendmdata.split(",");
            for (int i=0;i<pairs.length;i++){
                String[] keyvalue = pairs[i].split("=");
                String[] rowdata = new String[]{keyvalue[0], keyvalue[1]};
                matrixCursor.addRow(rowdata);
             }
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }

                Log.v("query", selection);
                return matrixCursor;
            }
        }
        else {
            Log.i("Query","Query for key");
            int size = ports.length;
            Integer avd = Integer.parseInt(myPort);
            avd = avd / 2;
            //File directory = getContext().getFilesDir();
            MatrixCursor matrixCursor = new MatrixCursor(new String[]{"key", "value"});
            try {
                    String keyhash = genHash(selection);
                    String myporthash = genHash(avd.toString());
                if (succ.equals("") && pred.equals("")) {
                    Log.i("Query","Query for key : when single node in list");
                            FileInputStream filestream = getContext().openFileInput(selection);
                            BufferedReader buf = new BufferedReader(new InputStreamReader(filestream));
                            String value = buf.readLine();
                            if (value != null) {
                                String[] rowdata = new String[]{selection, value};
                                Log.i(TAG, "query key we got : " + selection);
                                Log.i(TAG, "query- value we got : " + value);
                                matrixCursor.addRow(rowdata);
                                buf.close();
                            }
                }
                else if((pred.compareTo(myporthash)>0) && ((keyhash.compareTo(myporthash)<=0) || (keyhash.compareTo(pred)>0))){
                    // Checking if key lies behind the current node or after the pred
                    //File file = new File(directory, filelist[i]);
                    Log.i("Query","Query for key : when current node is head");
                    FileInputStream filestream = getContext().openFileInput(selection);
                    BufferedReader buf = new BufferedReader(new InputStreamReader(filestream));
                    String value = buf.readLine();
                    if (value != null) {
                        String[] rowdata = new String[]{selection, value};
                        Log.i(TAG, "query key we got : " + selection);
                        Log.i(TAG, "query- value we got : " + value);
                        matrixCursor.addRow(rowdata);
                        //String temp = selection + "=" + value;
                        buf.close();
                    }
                }
                else if(!(pred.compareTo(myporthash)>0) && ((keyhash.compareTo(myporthash)<=0) && (keyhash.compareTo(pred)>0) )){
                    Log.i("Query","Query for key : when current is not head");
                    FileInputStream filestream = getContext().openFileInput(selection);
                    BufferedReader buf = new BufferedReader(new InputStreamReader(filestream));
                    String value = buf.readLine();
                    if (value != null) {
                        String[] rowdata = new String[]{selection, value};
                        Log.i(TAG, "query key we got : " + selection);
                        Log.i(TAG, "query- value we got : " + value);
                        matrixCursor.addRow(rowdata);
                        //String temp = selection + "=" + value;
                        buf.close();
                    }
                }
                else{
                    Log.i("Query","Query for key : finding the socket");
                    String diff = selection + ":" + "query";
                    Integer portTosend =0;

                    for(int i=0;i<ports.length;i++){
                        if((i!=(size-1) && ((keyhash.compareTo(ports[i])>0) && (keyhash.compareTo(ports[i+1])<=0)))){
                            String temp = fileMap1.get(ports[i+1]);
                           portTosend = Integer.parseInt(temp)*2;
                        }
                        else if((keyhash.compareTo(ports[size-1])>0) || (keyhash.compareTo(ports[0])<=0)){
                            String temp =fileMap1.get(ports[0]);
                            portTosend = Integer.parseInt(temp)*2;
                        }
                    }
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            portTosend);
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true); // Output Stream that client uses to send messages
                    Log.i(TAG, "Message to send : " + diff);
                    out.println(diff); //Sends the message
                    Log.i(TAG, "Message sent " + diff);

                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    String ack = in.readLine();
                    in.close();
                    out.flush();
                    socket.close();

                    String[] rowdata = new String[]{selection, ack};
                    matrixCursor.addRow(rowdata);
                }

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            Log.v("query", selection);
            return matrixCursor;
        }
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

// Reference: https://docs.oracle.com/javase/tutorial/networking/sockets/definition.html
    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... msgs) {
                try {
                    if (msgs[1].trim().equals("new join")) {
                        try{
                        Log.i(TAG, "Client side : New join loop entry");
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(PORTS[0])); // Establishes a new socket creation for client/server communication
                        String msgToSend = msgs[0].trim() + ":" + msgs[1].trim();
                        Log.d(TAG, "Status of socket:" + socket.isConnected());
                        PrintWriter out = new PrintWriter(socket.getOutputStream(), true); // Output Stream that client uses to send messages
                        Log.i(TAG, "Message to send : " + msgToSend);
                        out.println(msgToSend); //Sends the message
                        Thread.sleep(50);
                        out.flush();
                        out.close();
                        socket.close();
                        Log.i(TAG, "client-side socket closed");
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }

                    } else if (msgs[1].trim().equals("update nodes")) {
                        Log.i(TAG, "Client side : update nodes loop entry");
                        try {
                            for (String s : portlist) {
                                Log.i(TAG, "For " + s + " broadcast");
                                String ab = fileMap.get(s);
                                Integer avdno = Integer.parseInt(ab);
                                Integer portNo = avdno * 2;
                                String msgToSend = msgs[0].trim() + ":" + msgs[1].trim() + ":" + avdno.toString() + ":" + msgs[2].trim();
                                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        portNo); //should create a new socket here or not?
                                PrintWriter out = new PrintWriter(socket.getOutputStream(), true); // Output Stream that client uses to send messages
                                Log.i(TAG, "Message to send : " + msgToSend);
                                out.println(msgToSend); //Sends the message
                                Thread.sleep(10);
                                Log.i(TAG, "Message sent " + msgToSend);

                                out.flush();
                                socket.close();
                            }
                        } catch (NullPointerException e) {
                            Log.e(TAG, "Null exception");
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                    else if (msgs[1].trim().equals("insert")) {
                        try {
                            Log.i(TAG, "Client side : Insert loop entry");
                            //String succ_befhash = fileMap.get(succ);
                            Log.i(TAG, "Succ before hash :" + succ_unhash);
                            Integer succ_port = Integer.parseInt(succ_unhash)*2;
                            Log.i(TAG, "Succ portno :" + succ_port);
                            Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    succ_port); // Establishes a new socket creation for client/server communication
                            String msgToSend = msgs[0].trim() + ":" + msgs[1].trim() + ":" + msgs[2].trim();
                            Log.d(TAG, "Status of socket:" + socket.isConnected());
                            PrintWriter out = new PrintWriter(socket.getOutputStream(), true); // Output Stream that client uses to send messages
                            Log.i(TAG, "Message to send : " + msgToSend);
                            Thread.sleep(10);
                            out.println(msgToSend); //Sends the message
                            out.flush();
                            out.close();
                            socket.close();
                            Log.i(TAG, "client-side socket closed");
                        } catch (Exception e){
                            Log.e(TAG, "Exception: " + e.getMessage());
                        }
                    }
                }catch (UnknownHostException e) {
                    Log.e(TAG, "ClientTask UnknownHostException");
                } catch (IOException e) {
                    Log.e(TAG, "ClientTask socket IOException" + e.getMessage());
                }
            return null;
        }

    }

    //Publishes updates on the UI. Invokes onProgressUpdate() every time publishProgress() is called.
    // Reference: https://developer.android.com/reference/android/os/AsyncTask
    // Reference: https://docs.oracle.com/javase/tutorial/networking/sockets/definition.html
    //Server sends an ACK message after successfully reading the client message
    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];
            while (true) {
                try {
                    Socket clientSocket = serverSocket.accept(); // Accepts the client's connection request
                    Log.i(TAG, "Server accepted connection");
                    BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); // Input stream that helps server read data from socket
                    String data = in.readLine();
                    Log.i(TAG, "Server side : Reading data " + data);
                    PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                    if ((data) != null) { // Receive data when not null
                        Log.i(TAG, data + " message received");
                        String[] sp = data.split(":");
                        if (sp[1].equals("new join")) {
                            Log.i(TAG, "Server side: join loop entry");
                            portlist.add(genHash(sp[0]));
                            fileMap.put(genHash(sp[0]), sp[0]);
                            Collections.sort(portlist);
                            String msg = "update nodes";
                            publishProgress(msg);
                            in.close();
                            clientSocket.close();
                            Log.i(TAG, "Server side : socket closed for new join");

                        } else if (sp[1].equals("update nodes")) {
                            Log.i(TAG, "Server side: update loop entry");
                            ports = sp[0].split(",");
                            unhashed = sp[3].split(",");
                            Log.i(TAG,"Sorted ports:" + Arrays.toString(ports));
                            for (int i = 0; i < unhashed.length; i++) {
                                fileMap1.put(genHash(unhashed[i]), unhashed[i]);
                            }
                            int a = ports.length;
                            Log.i(TAG, "Portlist size: " + a);
                            String hash = genHash(sp[2]);
                            for (int i = 0; i < a; i++) {
                                if ((ports[i]).equals(hash)) {
                                    Log.i(TAG, "Server side : computing succ and pred");
                                    if (a == 1) {
                                        pred = "";
                                        succ = "";
                                    } else if (i == 0) {
                                        pred = ports[a - 1];
                                        pred_unhash = unhashed[a - 1];
                                        succ = ports[i + 1];
                                        succ_unhash = unhashed[i + 1];
                                    } else if (i == (a - 1)) {
                                        //check = check + "," + "Pred:" + ports[i - 1] + "," + "Succ:" + ports[0];
                                        pred = ports[i - 1];
                                        pred_unhash = unhashed[i - 1];
                                        succ = ports[0];
                                        succ_unhash = unhashed[0];
                                        Log.i(TAG, "inside 4");
                                    } else {
                                        //check = check + "," + "Pred:" + ports[i - 1] + "," + "Succ:" + ports[i + 1];
                                        pred = ports[i - 1];
                                        pred_unhash = unhashed[i - 1];
                                        succ = ports[i + 1];
                                        succ_unhash = unhashed[i + 1];
                                        Log.i(TAG, "inside 5");
                                    }
                                }
                            }
                            Log.i(TAG, "Successor for " + sp[2] + ":" + succ);
                            Log.i(TAG, "Pred for " + sp[2] + ":" + pred);
                            Log.i(TAG, "Successor unhahsed for " + sp[2] + ":" + succ_unhash);
                            Log.i(TAG, "Pred unhashed for " + sp[2] + ":" + pred_unhash);
                            in.close();
                            clientSocket.close();
                            Log.i(TAG, "Server side : socket closed for node update");
                        } else if (sp[1].equals("delete all")) {
                            boolean flag;
                            String[] filelist = getContext().fileList();
                            File directory = getContext().getFilesDir();
                            for (int i = 0; i < filelist.length; i++) {
                                File file = new File(directory, filelist[i]);
                                if (file.exists()) {
                                    flag = file.delete();
                                    if (flag == true) {
                                        Log.i(TAG, "File" + i + "deleted");
                                    }
                                }
                            }
                        } else if (sp[1].equals("insert")) {
                            Log.i(TAG, "Server side : Insert");
                            String[] cvalues = sp[2].split(";");
                            ContentValues contentValues = new ContentValues();
                            contentValues.put(KEY_FIELD, (cvalues[0]));
                            contentValues.put(VALUE_FIELD, cvalues[1]);
                            getContext().getContentResolver().insert(uri, contentValues);
                        } else if (sp[1].equals("query all")) {
                            ArrayList<String> matrixdata = new ArrayList<String>();
                            String sendmdata="";
                            String[] filelist = getContext().fileList();
                            try {
                                for (int i = 0; i < filelist.length; i++) {
                                    //File file = new File(directory, filelist[i]);
                                    FileInputStream filestream = getContext().openFileInput(filelist[i]);
                                    BufferedReader buf = new BufferedReader(new InputStreamReader(filestream));
                                    String value = buf.readLine();
                                    if (value != null) {
                                        Log.i(TAG, "query key we got : " + filelist[i]);
                                        Log.i(TAG, "query- value we got : " + value);
                                        String temp = filelist[i] + "=" + value;
                                        matrixdata.add(temp);
                                        buf.close();
                                    }
                                }
                                //sendmdata = matrixdata.get(0);
                                for(int i=0;i<matrixdata.size();i++){
                                    sendmdata = sendmdata + matrixdata.get(i) + ",";
                                }
                                out.println(sendmdata);
                            }catch (Exception e){
                                Log.e(TAG, e.toString());
                            }
                        }
                        else if(sp[1].equals("query")) {
                            FileInputStream filestream = getContext().openFileInput(sp[0]);
                            BufferedReader buf = new BufferedReader(new InputStreamReader(filestream));
                            String value = buf.readLine();
                            if (value != null) {
                                out.println(value);
                                buf.close();
                            }
                        }
                        else if(sp[1].equals("key delete")){
                            boolean flag;
                            File directory = getContext().getFilesDir();
                            File file = new File(directory,sp[0]);
                            if (file.exists()) {
                                flag = file.delete();
                                if(flag==true) {
                                    Log.i(TAG, "File" + "deleted");
                                }
                            }
                        }
                    }

                } catch (IOException e) {
                    Log.e(TAG, e.toString());
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }


            }
        }
        protected void onProgressUpdate(String... strings) {
            /*
             * The following code displays what is received in doInBackground().
             */
            String strReceived = strings[0].trim();
            if (strReceived.equals("update nodes")) {
                String send= portlist.get(0);
                String hashmapdata = fileMap.get(send);
                for(int i=1;i<portlist.size();i++){
                    String temp = portlist.get(i);
                    String temp1 = fileMap.get(temp);
                    send = send + "," + temp;
                    hashmapdata = hashmapdata + "," + temp1;
//                    ports[i]=portlist.get(i);
                    Log.d("test", Arrays.toString(ports));
                    Log.d("test", "portslist - " + portlist.toString());
                    //Log.i(TAG, "Value at " + i + ":" + portlist.get(i));
                }
                //Log.i(TAG, "Port list into string for updation: "+ send);
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, send, strReceived, hashmapdata);
                Log.i(TAG, "Updation client call made on onprogressupdate");
            }
        }
    }
    private Uri buildUri(String scheme, String authority) {
        Uri.Builder uriBuilder = new Uri.Builder();
        uriBuilder.authority(authority);
        uriBuilder.scheme(scheme);
        return uriBuilder.build();
    }

}
