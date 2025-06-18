import wx
import psutil
import math
from threading import Thread
import time

class CircularGauge(wx.Panel):
    def __init__(self, parent, title, size=(120, 120), max_value=100):
        super().__init__(parent, size=size)
        self.title = title
        self.value = 0
        self.max_value = max_value
        self.size = size
        
        # Colors
        self.background_color = wx.Colour(240, 240, 240)
        self.gauge_bg_color = wx.Colour(220, 220, 220)
        self.gauge_colors = {
            'normal': wx.Colour(0, 120, 215),    # Blue
            'warning': wx.Colour(255, 140, 0),    # Orange
            'critical': wx.Colour(255, 0, 0)      # Red
        }
        self.text_color = wx.Colour(0, 0, 0)
        
        # Create buffer for double buffering
        self.buffer = wx.Bitmap(*size)
        
        # Bind events
        self.Bind(wx.EVT_PAINT, self.on_paint)
        self.Bind(wx.EVT_SIZE, self.on_size)
        
        # Initial draw
        self.update_drawing()
    
    def on_size(self, event):
        """Handle resize event"""
        size = self.GetSize()
        self.buffer = wx.Bitmap(size.width, size.height)
        self.update_drawing()
        event.Skip()
    
    def set_value(self, value):
        """Set the gauge value and trigger a redraw"""
        self.value = min(max(0, value), self.max_value)
        self.update_drawing()
    
    def get_gauge_color(self):
        """Get appropriate color based on value"""
        if self.value >= 90:
            return self.gauge_colors['critical']
        elif self.value >= 70:
            return self.gauge_colors['warning']
        return self.gauge_colors['normal']
    
    def update_drawing(self):
        """Update the gauge drawing"""
        try:
            # Create memory DC and graphics context
            mdc = wx.MemoryDC(self.buffer)
            gc = wx.GraphicsContext.Create(mdc)
            if not gc:
                return
            
            # Get dimensions
            width, height = self.GetSize()
            center_x = width / 2
            center_y = height / 2
            radius = min(width, height) / 2 - 15
            
            # Clear background
            gc.SetBrush(wx.Brush(self.background_color))
            gc.DrawRectangle(0, 0, width, height)
            
            # Draw gauge background circle
            gc.SetPen(wx.Pen(self.gauge_bg_color, 8))
            gc.SetBrush(wx.TRANSPARENT_BRUSH)
            gc.DrawEllipse(center_x - radius, center_y - radius, radius * 2, radius * 2)
            
            if self.value > 0:
                # Calculate angles in radians
                start_angle = -math.pi / 2  # Start at top (-90 degrees)
                sweep_angle = 2 * math.pi * (self.value / 100.0)  # Convert percentage to radians
                
                # Create path for arc
                path = gc.CreatePath()
                
                # Move to start position
                start_x = center_x + radius * math.cos(start_angle)
                start_y = center_y + radius * math.sin(start_angle)
                path.MoveToPoint(start_x, start_y)
                
                # Draw arc clockwise
                path.AddArc(center_x, center_y, radius, start_angle, start_angle + sweep_angle, True)
                
                # Draw value arc
                gc.SetPen(wx.Pen(self.get_gauge_color(), 8))
                gc.DrawPath(path)
            
            # Draw value with larger font first (in the center)
            value_font = wx.Font(14, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
            gc.SetFont(value_font, self.text_color)
            value_text = f"{int(self.value)}%"
            value_width = gc.GetTextExtent(value_text)[0]
            gc.DrawText(value_text, (width - value_width) / 2, center_y - 10)
            
            # Draw title below the gauge with more spacing
            title_font = wx.Font(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
            gc.SetFont(title_font, self.text_color)
            title_width = gc.GetTextExtent(self.title)[0]
            gc.DrawText(self.title, (width - title_width) / 2, height - 15)  # Moved up from bottom
            
            self.Refresh()
            
        except Exception as e:
            print(f"Error drawing gauge: {str(e)}")
    
    def on_paint(self, event):
        """Handle paint event"""
        dc = wx.BufferedPaintDC(self)
        if not dc:
            return
        dc.DrawBitmap(self.buffer, 0, 0)

class SystemMonitorPanel(wx.Panel):
    def __init__(self, parent):
        super().__init__(parent)
        
        # Create sizer
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        # Create gauges with larger size and more vertical space for title
        self.cpu_gauge = CircularGauge(self, "CPU", size=(150, 160))  # Increased height
        self.ram_gauge = CircularGauge(self, "RAM", size=(150, 160))  # Increased height
        
        # Add gauges to sizer with spacing
        sizer.Add(self.cpu_gauge, 0, wx.ALL | wx.ALIGN_CENTER, 10)
        sizer.AddSpacer(20)  # Add space between gauges
        sizer.Add(self.ram_gauge, 0, wx.ALL | wx.ALIGN_CENTER, 10)
        
        # Set sizer
        self.SetSizer(sizer)
        
        # Initialize monitoring
        self.running = True
        self.last_cpu = 0  # Store last CPU value for smoothing
        
        # Start monitoring in thread
        self.monitor_thread = Thread(target=self.update_stats, daemon=True)
        self.monitor_thread.start()
    
    def update_stats(self):
        """Update system statistics"""
        while self.running:
            try:
                # Get CPU usage with smoothing
                current_cpu = psutil.cpu_percent(interval=0.5)
                smoothed_cpu = (self.last_cpu + current_cpu) / 2
                self.last_cpu = current_cpu
                
                # Get RAM usage
                ram = psutil.virtual_memory()
                ram_percent = ram.percent
                
                # Update gauges in thread-safe way
                if self and wx.IsMainThread():
                    self.cpu_gauge.set_value(smoothed_cpu)
                    self.ram_gauge.set_value(ram_percent)
                else:
                    wx.CallAfter(self.cpu_gauge.set_value, smoothed_cpu)
                    wx.CallAfter(self.ram_gauge.set_value, ram_percent)
                
                time.sleep(1)
            except Exception as e:
                print(f"Error updating system stats: {str(e)}")
                time.sleep(1)
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.running = False
        if hasattr(self, 'monitor_thread') and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=1) 