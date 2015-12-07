package packet;

public abstract class PacketAnalyzerRunnable implements Runnable {
    protected boolean keepRunning = true;
    
    public final synchronized void requestStop() {
        this.keepRunning = false;
    }
    
    protected abstract String threadName();
    
    protected void init() {}
    protected abstract void runLoop();

    public void run() {
        final String orgName = Thread.currentThread().getName();
        Thread.currentThread().setName(orgName + " - " + this.threadName());
        this.init();
        
        while (this.keepRunning)
            this.runLoop();
    }
}
