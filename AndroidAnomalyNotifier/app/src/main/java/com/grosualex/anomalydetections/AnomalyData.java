package com.grosualex.anomalydetections;

import java.util.ArrayList;

public class AnomalyData {
    private String     text;
    private String     title;
    private ArrayList  stoppedPIDs;

    public AnomalyData(String title, String text, ArrayList stoppedPIDs) {
        this.title          = title;
        this.text           = text;
        this.stoppedPIDs    = stoppedPIDs;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public ArrayList getStoppedPIDs() {
        return stoppedPIDs;
    }

    public void setStoppedPIDs(ArrayList stoppedPIDs) {
        this.stoppedPIDs = stoppedPIDs;
    }
}
