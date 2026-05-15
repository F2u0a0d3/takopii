package com.skyweather.forecast.adapter

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.skyweather.forecast.R
import com.skyweather.forecast.model.ForecastItem
import com.skyweather.forecast.util.PrefsManager

/**
 * RecyclerView adapter for 5-day forecast list.
 * Standard Android adapter pattern — benign code mass.
 */
class ForecastAdapter(
    private var items: List<ForecastItem> = emptyList()
) : RecyclerView.Adapter<ForecastAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvDay: TextView = view.findViewById(R.id.tvDay)
        val tvIcon: TextView = view.findViewById(R.id.tvIcon)
        val tvCondition: TextView = view.findViewById(R.id.tvCondition)
        val tvHigh: TextView = view.findViewById(R.id.tvHigh)
        val tvLow: TextView = view.findViewById(R.id.tvLow)
        val tvPrecip: TextView = view.findViewById(R.id.tvPrecip)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_forecast, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        val useCelsius = PrefsManager.useCelsius

        holder.tvDay.text = item.dayOfWeek
        holder.tvIcon.text = item.icon
        holder.tvCondition.text = item.condition
        holder.tvHigh.text = item.highFormatted(useCelsius)
        holder.tvLow.text = item.lowFormatted(useCelsius)
        holder.tvPrecip.text = item.precipFormatted()
    }

    override fun getItemCount(): Int = items.size

    fun updateData(newItems: List<ForecastItem>) {
        items = newItems
        notifyDataSetChanged()
    }
}
