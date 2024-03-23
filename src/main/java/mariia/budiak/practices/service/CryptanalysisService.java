package mariia.budiak.practices.service;

import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
public class CryptanalysisService {

    public HashMap<Character, Integer> getFrequencyAnalysis(String phrase){
        var freqMap = new HashMap<Character, Integer>();
        for(var ch: CommonAffineFunctionality.ALPHABET){
            freqMap.put(ch, 0);
        }
        for(var ch: phrase.toCharArray()){
            if(freqMap.containsKey(ch)){
                var oldFreq = freqMap.get(ch);
                freqMap.put(ch, oldFreq+1);
            }
        }
        return freqMap;
    }

}
