package com.skyweather.forecast

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.appbar.MaterialToolbar
import com.skyweather.forecast.adapter.CityAdapter
import com.skyweather.forecast.model.CityDatabase
import com.skyweather.forecast.util.PrefsManager

/**
 * City search screen.
 * User selects a city to view weather for.
 * Pure benign UI — interaction tracking for evasion gate.
 */
class SearchActivity : AppCompatActivity() {

    private lateinit var adapter: CityAdapter
    private lateinit var tvNoResults: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_search)

        setupToolbar()
        setupSearch()
        setupRecyclerView()

        // Show all cities initially
        adapter.updateData(CityDatabase.cities)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        PrefsManager.incrementInteraction()
    }

    private fun setupToolbar() {
        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { onBackPressedDispatcher.onBackPressed() }
    }

    private fun setupSearch() {
        tvNoResults = findViewById(R.id.tvNoResults)
        val etSearch = findViewById<EditText>(R.id.etSearch)

        etSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val query = s?.toString() ?: ""
                val results = CityDatabase.search(query)
                adapter.updateData(results)
                tvNoResults.visibility = if (results.isEmpty()) View.VISIBLE else View.GONE
            }
        })
    }

    private fun setupRecyclerView() {
        adapter = CityAdapter(emptyList()) { city ->
            PrefsManager.currentCity = city.name
            finish()
        }
        val rv = findViewById<RecyclerView>(R.id.rvCities)
        rv.layoutManager = LinearLayoutManager(this)
        rv.adapter = adapter
    }
}
