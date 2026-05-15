package com.skyweather.forecast.adapter

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.skyweather.forecast.R
import com.skyweather.forecast.model.City

/**
 * RecyclerView adapter for city search results.
 */
class CityAdapter(
    private var cities: List<City> = emptyList(),
    private val onCitySelected: (City) -> Unit
) : RecyclerView.Adapter<CityAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvCityName: TextView = view.findViewById(R.id.tvCityName)
        val tvCountry: TextView = view.findViewById(R.id.tvCountry)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_city, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val city = cities[position]
        holder.tvCityName.text = city.name
        holder.tvCountry.text = city.country
        holder.itemView.setOnClickListener { onCitySelected(city) }
    }

    override fun getItemCount(): Int = cities.size

    fun updateData(newCities: List<City>) {
        cities = newCities
        notifyDataSetChanged()
    }
}
