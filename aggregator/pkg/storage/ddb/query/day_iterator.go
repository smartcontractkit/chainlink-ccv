package query

import (
	"time"
)

type DayIterator struct {
	current time.Time
	end     time.Time
	done    bool
}

func NewDayIterator(start, end int64, dateTimeOfEarliestRecord time.Time, paginationToken *AggregatedReportPaginationToken) *DayIterator {
	startDay := time.Unix(start, 0).UTC()
	endDay := time.Unix(end, 0).UTC()

	if startDay.Before(dateTimeOfEarliestRecord) {
		startDay = dateTimeOfEarliestRecord
	}

	if paginationToken != nil {
		// Resume from the day in the pagination token.
		tokenDay, err := time.Parse("2006-01-02", paginationToken.LastDay)
		if err == nil && tokenDay.After(startDay) {
			startDay = tokenDay
		}
	}

	startDate := time.Date(startDay.Year(), startDay.Month(), startDay.Day(), 0, 0, 0, 0, time.UTC)
	endDate := time.Date(endDay.Year(), endDay.Month(), endDay.Day(), 0, 0, 0, 0, time.UTC)

	return &DayIterator{
		current: startDate,
		end:     endDate,
		done:    false,
	}
}

func (it *DayIterator) Next() bool {
	if it.done {
		return false
	}

	if it.current.After(it.end) {
		it.done = true
		return false
	}

	return true
}

func (it *DayIterator) Done() bool {
	return it.done
}

func (it *DayIterator) Day() string {
	return it.current.Format("2006-01-02")
}

func (it *DayIterator) Advance() {
	it.current = it.current.AddDate(0, 0, 1)
}
