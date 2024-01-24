package metrics

import "fmt"

type Staty struct {
	Fqdn string
}

func (f Staty) String() string {
	return fmt.Sprintf("fqdn:%s", f.Fqdn)
}

type StatyMap map[uint16]map[string][]Staty

func NewStatyMap() StatyMap {
	sm := make(StatyMap)
	return sm
}

func (s StatyMap) Add(key uint16, subKey string, value Staty) {
	if _, ok := s[key]; !ok {
		s[key] = make(map[string][]Staty)
	}

	for _, existingStaty := range s[key][subKey] {
		if existingStaty == value {
			// Value already exist, do not add
			return
		}
	}

	// Add unique value
	s[key][subKey] = append(s[key][subKey], value)
}

// Remove removes a Staty from the StatyMap
func (s StatyMap) Remove(key uint16, subKey string, value Staty) {
	if subMap, ok := s[key]; ok {
		if staties, ok := subMap[subKey]; ok {
			for i, staty := range staties {
				if staty == value {
					// Remove the Staty from the slice
					s[key][subKey] = append(staties[:i], staties[i+1:]...)
					// If the slice is empty, remove subKey from the map
					if len(s[key][subKey]) == 0 {
						delete(s[key], subKey)
						// If the map is empty, remove the key from StatyMap
						if len(s[key]) == 0 {
							delete(s, key)
						}
					}
					return
				}
			}
		}
	}
}
